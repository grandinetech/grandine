namespace Grandine.NethermindPlugin;

using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;

using Autofac;

using Nethermind.Api;
using Nethermind.Api.Extensions;
using Nethermind.Core;
using Nethermind.Logging;
using Nethermind.Merge.Plugin;

public class GrandinePlugin(IGrandineConfig grandineConfig) : INethermindPlugin
{
    private readonly List<string> arguments = new List<string>();

    #pragma warning disable CS8618
    private INethermindApi api;

    private ILogger logger;

    private GrandineClient? client;

    public string Name => "Grandine plugin";

    public string Description => "Nethermind plugin to enable embedded grandine CL client";

    public string Author => "Grandine team";

    public bool Enabled => grandineConfig.Enabled;

    public Task Init(INethermindApi nethermindApi)
    {
        this.api = nethermindApi;
        this.logger = nethermindApi.LogManager.GetClassLogger();
        this.logger.Info("Initializing grandine plugin...");

        var configInterface = typeof(IGrandineConfig);

        PropertyInfo[] properties = configInterface.GetProperties(BindingFlags.Public | BindingFlags.Instance);

        if (grandineConfig.Network == null)
        {
            (IApiWithStores getFromApi, _) = nethermindApi.ForInit;
            this.arguments.Add("--network");
            this.arguments.Add(BlockchainIds.GetBlockchainName(getFromApi.ChainSpec.ChainId).ToLower());
        }

        foreach (PropertyInfo prop in properties)
        {
            GrandineConfigItemAttribute? attribute = prop.GetCustomAttribute<GrandineConfigItemAttribute>();

            if (attribute == null)
            {
                continue;
            }

            object? value = prop.GetValue(grandineConfig);

            if (value == null)
            {
                continue;
            }

            Type type = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;

            if (type == typeof(bool))
            {
                if ((bool)value)
                {
                    this.arguments.Add(attribute.Name);
                }
            }
            else if (type == typeof(string))
            {
                this.arguments.Add(attribute.Name);
                this.arguments.Add((string)value);
            }
            else
            {
                throw new NotSupportedException($"Unrecognized option {attribute.Name} of type {prop.PropertyType}");
            }
        }

        this.logger.Debug($"Parsed grandine arguments: {string.Join(", ", this.arguments)}");

        return Task.CompletedTask;
    }

    public Task InitRpcModules()
    {
        this.logger.Debug("Initializing grandine RPC...");
        if (this.api is null)
        {
            return Task.CompletedTask;
        }

        IEngineRpcModule engineRpcModule = this.api.Context.Resolve<IEngineRpcModule>();

        var api = new GrandineEngineApi(this.logger, engineRpcModule);

        this.client = new GrandineClient(api);
        this.logger.Info($"Starting grandine with arguments: {string.Join(", ", this.arguments)}");
        this.client.Run(this.arguments.ToArray());
        this.api.DisposeStack.Push(this.client);

        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => default;
}