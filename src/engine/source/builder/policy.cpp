#include "policy.hpp"

#include "registry.hpp"
namespace builder
{

Asset::Type getAssetType(const std::string& name)
{
    if (DECODERS == name)
    {
        return Asset::Type::DECODER;
    }
    else if (RULES == name)
    {
        return Asset::Type::RULE;
    }
    else if (OUTPUTS == name)
    {
        return Asset::Type::OUTPUT;
    }
    else if (FILTERS == name)
    {
        return Asset::Type::FILTER;
    }
    else
    {
        // TODO: should this be a logic_error?
        throw std::runtime_error(fmt::format("Engine environment: Unknown type of asset \"{}\".", name));
    }
}

void Policy::buildGraph(const std::vector<std::shared_ptr<Asset>>& assets, const std::string& graphName)
{
    auto graphPos = std::find_if(
        m_graphs.begin(), m_graphs.end(), [&graphName](const auto& graph) { return std::get<0>(graph) == graphName; });
    auto& graph = std::get<1>(*graphPos);
    for (auto& asset : assets)
    {
        // Build Asset object and insert
        graph.addNode(asset->m_name, asset);
        if (asset->m_parents.empty())
        {
            graph.addEdge(graph.rootId(), asset->m_name);
        }
        else
        {
            for (auto& parent : asset->m_parents)
            {
                graph.addEdge(parent, asset->m_name);
            }
        }
    }
}

void Policy::addFilters(const std::string& graphName)
{
    auto graphPos = std::find_if(
        m_graphs.begin(), m_graphs.end(), [&graphName](const auto& graph) { return std::get<0>(graph) == graphName; });
    auto& graph = std::get<1>(*graphPos);
    for (auto& [name, asset] : m_assets)
    {
        if (Asset::Type::FILTER == asset->m_type)
        {
            for (auto& parent : asset->m_parents)
            {
                if (graph.hasNode(parent))
                {
                    graph.injectNode(name, asset, parent);
                }
            }
        }
    }
}

std::unordered_map<std::string, std::vector<std::shared_ptr<Asset>>>
Policy::getManifestAssets(const json::Json& jsonDefinition,
                               std::shared_ptr<const store::IStoreRead> storeRead,
                               std::shared_ptr<internals::Registry> registry)
{
    if (!jsonDefinition.isObject())
    {
        throw std::runtime_error("Manifest is not an object");
    }

    auto manifestObj = jsonDefinition.getObject().value();

    // Get name
    auto nameIt = std::find_if(
        manifestObj.begin(), manifestObj.end(), [](const auto& tuple) { return std::get<0>(tuple) == "name"; });
    if (nameIt == manifestObj.end())
    {
        throw std::runtime_error("Manifest name is missing");
    }
    auto nameOpt = std::get<1>(*nameIt).getString();
    if (!nameOpt)
    {
        throw std::runtime_error("Manifest name is not a string");
    }

    manifestObj.erase(nameIt);

    std::unordered_map<std::string, std::vector<std::shared_ptr<Asset>>> assets;

    for (auto& [key, value] : manifestObj)
    {
        if (key == DECODERS || key == RULES || key == OUTPUTS || key == FILTERS)
        {
            if (!value.isArray())
            {
                throw std::runtime_error(fmt::format(R"(Manifest "{}" is not an array)", key));
            }

            auto assetNames = value.getArray().value();
            std::vector<std::shared_ptr<Asset>> assetList;
            auto assetType = getAssetType(key);

            std::transform(assetNames.begin(),
                           assetNames.end(),
                           std::back_inserter(assetList),
                           [&](const auto& assetName)
                           {
                               auto name = assetName.getString();
                               if (!name)
                               {
                                   throw std::runtime_error("Asset name is not a string");
                               }

                               auto assetDef = storeRead->get(name.value());
                               if (std::holds_alternative<base::Error>(assetDef))
                               {
                                   throw std::runtime_error(fmt::format(
                                       "Error loading {}: ", name.value(), std::get<base::Error>(assetDef).message));
                               }

                               return std::make_shared<Asset>(std::get<json::Json>(assetDef), assetType, registry);
                           });

            assets[key] = assetList;
        }
    }

    return assets;
}

std::string Policy::name() const
{
    return m_name;
}

std::unordered_map<std::string, std::shared_ptr<Asset>>& Policy::assets()
{
    return m_assets;
}

const std::unordered_map<std::string, std::shared_ptr<Asset>>& Policy::assets() const
{
    return m_assets;
}

std::string Policy::getGraphivzStr()
{
    std::stringstream ss;
    ss << "digraph G {" << std::endl;
    ss << "compound=true;" << std::endl;
    ss << fmt::format("fontname=\"Helvetica,Arial,sans-serif\";") << std::endl;
    ss << fmt::format("fontsize=12;") << std::endl;
    ss << fmt::format("node [fontname=\"Helvetica,Arial,sans-serif\", "
                      "fontsize=10];")
       << std::endl;
    ss << fmt::format("edge [fontname=\"Helvetica,Arial,sans-serif\", "
                      "fontsize=8];")
       << std::endl;
    ss << "environment [label=\"" << m_name << "\", shape=Mdiamond];" << std::endl;

    auto removeHyphen = [](const std::string& text)
    {
        auto ret = text;
        auto pos = ret.find("-");
        while (pos != std::string::npos)
        {
            ret.erase(pos, 1);
            pos = ret.find("-");
        }

        pos = ret.find("/");
        while (pos != std::string::npos)
        {
            ret.erase(pos, 1);
            pos = ret.find("/");
        }

        return ret;
    };

    for (auto& [name, graph] : m_graphs)
    {
        ss << std::endl;
        ss << "subgraph cluster_" << name << " {" << std::endl;
        ss << "label=\"" << name << "\";" << std::endl;
        ss << "style=filled;" << std::endl;
        ss << "color=lightgrey;" << std::endl;
        ss << fmt::format("node [style=filled,color=white];") << std::endl;
        for (auto& [name, asset] : graph.nodes())
        {
            ss << removeHyphen(name) << " [label=\"" << name << "\"];" << std::endl;
        }
        for (auto& [parent, children] : graph.edges())
        {
            for (auto& child : children)
            {
                ss << removeHyphen(parent) << " -> " << removeHyphen(child) << ";" << std::endl;
            }
        }
        ss << "}" << std::endl;
        ss << "environment -> " << name << "Input;" << std::endl;
    }
    ss << "}\n";
    return ss.str();
}

base::Expression Policy::getExpression() const
{
    // Expression of the environment, expression to be returned.
    // All subgraphs are added to this expression.
    std::shared_ptr<base::Operation> environment = base::Chain::create(m_name, {});

    // Generate the graph in order decoders->rules->outputs
    for (auto& [graphName, graph] : m_graphs)
    {
        // Create root subgraph expression
        std::shared_ptr<base::Operation> inputExpression;
        switch (graph.node(graph.rootId())->m_type)
        {
            case Asset::Type::DECODER:
                inputExpression = base::Or::create(graph.node(graph.rootId())->m_name, {});
                break;
            case Asset::Type::RULE:
            case Asset::Type::OUTPUT:
                inputExpression = base::Broadcast::create(graph.node(graph.rootId())->m_name, {});
                break;
            default:
                throw std::runtime_error(fmt::format("Building environment \"{}\" failed as the type of the "
                                                     "asset \"{}\" is not supported",
                                                     graphName,
                                                     graph.node(graph.rootId())->m_name));
        }
        // Add input Expression to environment expression
        environment->getOperands().push_back(inputExpression);

        // Build rest of the graph

        // Avoid duplicating nodes when multiple
        // parents has the same child node
        std::map<std::string, base::Expression> builtNodes;

        // parentNode Expression is passed as filters need it.
        auto visit = [&](const std::string& current, const std::string& parent, auto& visitRef) -> base::Expression
        {
            // If node is already built, return it
            if (builtNodes.find(current) != builtNodes.end())
            {
                return builtNodes[current];
            }
            else
            {
                // Create node
                // If node has children, create an auxiliary Implication node, with
                // asset as condition and children as consequence, otherwise create an
                // asset node.
                auto asset = graph.node(current);
                std::shared_ptr<base::Operation> assetNode;

                if (graph.hasChildren(current))
                {
                    std::shared_ptr<base::Operation> assetChildren;

                    // Children expression depends on the type of the asset
                    auto type = asset->m_type;

                    // If Filter type is the same as the parent
                    if (type == Asset::Type::FILTER)
                    {
                        type = m_assets.at(parent)->m_type;
                    }

                    switch (type)
                    {
                        case Asset::Type::DECODER: assetChildren = base::Or::create("children", {}); break;
                        case Asset::Type::RULE:
                        case Asset::Type::OUTPUT: assetChildren = base::Broadcast::create("children", {}); break;

                        default:
                            throw std::runtime_error(
                                fmt::format("Asset type not supported from asset \"{}\"", current));
                    }

                    assetNode =
                        base::Implication::create(asset->m_name + "Node", asset->getExpression(), assetChildren);

                    // Visit children and add them to the children node
                    for (auto& child : graph.children(current))
                    {
                        assetChildren->getOperands().push_back(visitRef(child, current, visitRef));
                    }
                }
                else
                {
                    // No children
                    assetNode = asset->getExpression()->getPtr<base::Operation>();
                }

                // Add it to builtNodes
                if (asset->m_parents.size() > 1)
                {
                    builtNodes.insert(std::make_pair(current, assetNode));
                }

                return assetNode;
            }
        };

        // Visit root childs and add them to the root expression
        for (auto& child : graph.children(graph.rootId()))
        {
            inputExpression->getOperands().push_back(visit(child, graph.rootId(), visit));
        }
    }

    return environment;
}

} // namespace builder
