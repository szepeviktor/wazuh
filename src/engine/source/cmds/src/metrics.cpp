#include <cmds/metrics.hpp>

#include <eMessages/metrics.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"
#include <cmds/apiclnt/client.hpp>

#include <json/json.hpp>
#include <metrics/include/metrics.hpp>


namespace
{

struct Options
{
    std::string apiEndpoint;
    std::string instrumentName;
    bool enableState;
};

} // namespace

namespace  cmd::metrics
{

namespace eMetrics = ::com::wazuh::api::engine::metrics;
namespace eEngine = ::com::wazuh::api::engine;

void runDump(std::shared_ptr<apiclnt::Client> client)
{
    using RequestType = eMetrics::Dump_Request;
    using ResponseType = eMetrics::Dump_Response;
    const std::string command = "metrics/dump";

    RequestType eRequest;

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print value as json
    const auto& value = eResponse.value();
    const auto json = eMessage::eMessageToJson<google::protobuf::Value>(value);
    std::cout << std::get<std::string>(json) << std::endl;
}

void runGetInstrument(std::shared_ptr<apiclnt::Client> client, const std::string& name)
{
    using RequestType = eMetrics::Get_Request;
    using ResponseType = eMetrics::Get_Response;
    const std::string command = "metrics/get";

    // Prepare the request
    RequestType eRequest;
    eRequest.set_name(name);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print value as json
    const auto& value = eResponse.value();
    const auto json = eMessage::eMessageToJson<google::protobuf::Value>(value);
    std::cout << std::get<std::string>(json) << std::endl;
}

void runEnableInstrument(std::shared_ptr<apiclnt::Client> client, const std::string& name, bool status)
{
    using RequestType = eMetrics::Enable_Request;
    using ResponseType = eMetrics::Enable_Response;
    const std::string command = "metrics/enable";

    RequestType eRequest;
    eRequest.set_name(name);
    eRequest.set_status(status);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void runListInstruments(std::shared_ptr<apiclnt::Client> client)
{
    using RequestType = eMetrics::List_Request;
    using ResponseType = eMetrics::List_Response;
    const std::string command = "metrics/list";

    RequestType eRequest;

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print value as json
    const auto& value = eResponse.value();
    const auto json = eMessage::eMessageToJson<google::protobuf::Value>(value);
    std::cout << std::get<std::string>(json) << std::endl;
}

void runTest(std::shared_ptr<apiclnt::Client> client)
{
    using RequestType = eMetrics::Test_Request;
    using ResponseType = eMetrics::Test_Response;
    const std::string command = "metrics/test";

    RequestType eRequest;

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);
}

void configure(CLI::App_p app)
{
    auto metricApp = app->add_subcommand("metrics", "Manage the engine's Metrics Module.");
    metricApp->require_subcommand(1);
    auto options = std::make_shared<Options>();

    // Endpoint
    metricApp->add_option("-a, --api_socket", options->apiEndpoint, "engine api address")->default_val(ENGINE_API_SOCK);
    const auto client = std::make_shared<apiclnt::Client>(options->apiEndpoint);

    // metrics subcommands
    // dump
    auto dump_subcommand = metricApp->add_subcommand(details::API_METRICS_DUMP_SUBCOMMAND, "Prints all collected metrics.");
    dump_subcommand->callback([options, client]() { runDump(client);});

    // get
    auto get_subcommand = metricApp->add_subcommand("get", "Print a single metric as json.");
    get_subcommand->add_option("Instrument name", options->instrumentName, "Name that identifies the instrument.")
    ->required();
    get_subcommand->callback([options, client]() { runGetInstrument(client, options->instrumentName); });

    // enable
    auto enable_subcommand = metricApp->add_subcommand(details::API_METRICS_ENABLE_SUBCOMMAND, "Enable or disable a specific instrument.");
    enable_subcommand
    ->add_option("Instrument name", options->instrumentName, "Name of the instrument whose status will be modified.")
    ->required();
    enable_subcommand->add_option("Enable state", options->enableState, "New instrument status.")->required();
    enable_subcommand->callback(
    [options, client]() { runEnableInstrument(client, options->instrumentName, options->enableState); });

    // list
    auto list_subcommand = metricApp->add_subcommand(details::API_METRICS_LIST_SUBCOMMAND, "Prints name, status and instruments types.");
    list_subcommand->callback([options, client]() { runListInstruments(client); });

    // test
    auto test_subcommand = metricApp->add_subcommand(details::API_METRICS_TEST_SUBCOMMAND, "Generate dummy metrics for testing.");
    test_subcommand->callback([client]() { runTest(client); });
}

} // namespace cmd::metrics
