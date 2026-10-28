/**
 * @file tests/unit/test_nvhttp_https.cpp
 * @brief Verify HTTPS callbacks retain the guard protecting server lifetime, and that closing an HTTPS stream does not wait on the peer.
 */

// test includes
#include "../tests_common.h"

// standard includes
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <thread>

// local includes
#include <src/crypto.h>
#include <src/nvhttp.h>

namespace {
  using namespace std::chrono_literals;
  using boost::asio::ip::tcp;

  /**
   * @brief Run real HTTPS callbacks against an isolated loopback listener.
   */
  struct HttpsHandlerLifetimeTest: BaseTest {
    /**
     * @brief Create credentials and start the production HTTPS accept handler.
     */
    void SetUp() override {
      BaseTest::SetUp();
      const auto credentials = crypto::gen_creds("Sunshine HTTPS lifetime test", 2048);
      certificate_file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "https_lifetime_cert.pem";
      private_key_file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "https_lifetime_key.pem";
      std::ofstream {certificate_file} << credentials.x509;
      std::ofstream {private_key_file} << credentials.pkey;

      server = nvhttp::test_support::make_https_server(certificate_file.string(), private_key_file.string(), handler_scope);
      server->io_service = std::make_shared<boost::asio::io_context>();
      server->config.address = "127.0.0.1";
      server->config.port = 0;
      server->start([this](unsigned short assigned_port) {
        port = assigned_port;
      });
      server->io_service->poll();
      ASSERT_NE(port, 0);
    }

    /**
     * @brief Drain canceled callbacks and remove the generated credentials.
     */
    void TearDown() override {
      if (server) {
        server->stop();
        server->io_service->restart();
        server->io_service->poll();
        server.reset();
      }
      if (stop_thread.joinable()) {
        stop_thread.join();
      }
      std::error_code cleanup_error;
      std::filesystem::remove(certificate_file, cleanup_error);
      std::filesystem::remove(private_key_file, cleanup_error);
      BaseTest::TearDown();
    }

    /**
     * @brief Check that stopping the scope runner waits until the error callback exits.
     *
     * @param callback_error Error delivered by the real accept or TLS handshake operation.
     */
    void check_handler_guard(const boost::system::error_code &callback_error) {
      EXPECT_TRUE(callback_error);
      ++error_callbacks;
      std::promise<void> stopping;
      auto stopping_future = stopping.get_future();
      std::promise<void> stopped;
      stopped_future = stopped.get_future();
      stop_thread = std::jthread([this, stopping = std::move(stopping), stopped = std::move(stopped)]() mutable {
        stopping.set_value();
        handler_scope->stop();
        stopped.set_value();
      });
      stopping_future.wait();
      EXPECT_EQ(stopped_future.wait_for(50ms), std::future_status::timeout);
    }

    std::unique_ptr<SimpleWeb::ServerBase<nvhttp::SunshineHTTPS>> server;  ///< Server running production accept and handshake callbacks.
    std::shared_ptr<SimpleWeb::ScopeRunner> handler_scope;  ///< Guard used by the server destructor.
    std::jthread stop_thread;  ///< Concurrent attempt to stop the handler scope.
    std::future<void> stopped_future;  ///< Signals that all callback guards have been released.
    unsigned short port = 0;  ///< Assigned loopback port.
    int error_callbacks = 0;  ///< Number of errors delivered while testing a handler.
    std::filesystem::path certificate_file;  ///< Generated server certificate.
    std::filesystem::path private_key_file;  ///< Generated server private key.
  };

  /**
   * @brief Canceling a pending accept holds the server guard through its error callback.
   */
  TEST_F(HttpsHandlerLifetimeTest, AcceptErrorRetainsGuardUntilCallbackReturns) {
    server->on_error = [this](auto, const auto &callback_error) {
      check_handler_guard(callback_error);
    };
    server->stop();
    server->io_service->run_for(2s);
    ASSERT_EQ(error_callbacks, 1);
    ASSERT_TRUE(stopped_future.valid());
    EXPECT_EQ(stopped_future.wait_for(2s), std::future_status::ready);
  }

  /**
   * @brief A failed TLS handshake holds the server guard through its error callback.
   */
  TEST_F(HttpsHandlerLifetimeTest, HandshakeErrorRetainsGuardUntilCallbackReturns) {
    server->on_error = [this](auto, const auto &callback_error) {
      check_handler_guard(callback_error);
    };
    boost::asio::io_context client_io;
    tcp::socket client {client_io};
    client.connect({boost::asio::ip::address_v4::loopback(), port});
    client.close();
    server->io_service->run_for(2s);
    ASSERT_EQ(error_callbacks, 1);
    ASSERT_TRUE(stopped_future.valid());
    EXPECT_EQ(stopped_future.wait_for(2s), std::future_status::ready);
  }

  /**
   * @brief A stopped server scope prevents a canceled accept from dispatching an error.
   */
  TEST_F(HttpsHandlerLifetimeTest, StoppedScopeSkipsAcceptCallback) {
    server->on_error = [this](auto, const auto &) {
      ++error_callbacks;
    };
    handler_scope->stop();
    server->stop();
    server->io_service->run_for(2s);
    EXPECT_EQ(error_callbacks, 0);
  }

  /**
   * @brief A stopped server scope prevents an outstanding handshake from dispatching an error.
   */
  TEST_F(HttpsHandlerLifetimeTest, StoppedScopeSkipsHandshakeCallback) {
    server->on_error = [this](auto, const auto &) {
      ++error_callbacks;
    };
    boost::asio::io_context client_io;
    tcp::socket client {client_io};
    client.connect({boost::asio::ip::address_v4::loopback(), port});
    server->io_service->poll();
    handler_scope->stop();
    client.close();
    server->io_service->run_for(2s);
    EXPECT_EQ(error_callbacks, 0);
  }

  /**
   * @brief Destroying an established HTTPS stream does not wait for the peer's close_notify.
   *
   * The destructor runs on the HTTPS server's only thread, so waiting here would stall every
   * later request for as long as a client that has gone away keeps its connection open.
   */
  TEST(SunshineHttpsShutdownTest, DestructorDoesNotWaitForPeerCloseNotify) {
    const auto credentials = crypto::gen_creds("Sunshine HTTPS shutdown test", 2048);
    boost::asio::ssl::context server_context {boost::asio::ssl::context::tls_server};
    server_context.use_certificate_chain(boost::asio::buffer(credentials.x509));
    server_context.use_private_key(boost::asio::buffer(credentials.pkey), boost::asio::ssl::context::pem);
    boost::asio::ssl::context client_context {boost::asio::ssl::context::tls_client};
    client_context.set_verify_mode(boost::asio::ssl::verify_none);

    boost::asio::io_context io_context;
    tcp::acceptor acceptor {io_context, {boost::asio::ip::address_v4::loopback(), 0}};
    auto server = std::make_unique<nvhttp::SunshineHTTPS>(io_context, server_context);
    boost::asio::ssl::stream<tcp::socket> client {io_context, client_context};
    client.lowest_layer().connect(acceptor.local_endpoint());
    acceptor.accept(server->lowest_layer());

    auto client_handshake = std::async(std::launch::async, [&client]() {
      boost::system::error_code handshake_error;
      client.handshake(boost::asio::ssl::stream_base::client, handshake_error);
      return handshake_error;
    });
    boost::system::error_code server_handshake_error;
    server->handshake(boost::asio::ssl::stream_base::server, server_handshake_error);
    const auto client_handshake_error = client_handshake.get();
    ASSERT_FALSE(server_handshake_error) << server_handshake_error.message();
    ASSERT_FALSE(client_handshake_error) << client_handshake_error.message();

    // The client stays connected but never reads or answers, like a peer whose close was lost.
    auto destroyed = std::async(std::launch::async, [&server]() {
      server.reset();
    });
    const auto status = destroyed.wait_for(2s);
    if (status != std::future_status::ready) {
      // Unblock a destructor that is waiting for the peer, so the test can finish.
      boost::system::error_code close_error;
      client.lowest_layer().close(close_error);
    }
    destroyed.wait();
    EXPECT_EQ(status, std::future_status::ready);
  }
}  // namespace
