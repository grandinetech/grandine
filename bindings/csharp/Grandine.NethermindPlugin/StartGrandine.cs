namespace Grandine.NethermindPlugin;

using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

using Nethermind.Api.Steps;
using Nethermind.Core;
using Nethermind.Init.Steps;
using Nethermind.Logging;
using Nethermind.Merge.Plugin;
using Nethermind.Specs.ChainSpecStyle;

[RunnerStepDependencies(typeof(RegisterRpcModules))]
public class StartGrandine(
    IGrandineConfig grandineConfig,
    ChainSpec chainSpec,
    IEngineRpcModule engineRpcModule,
    IDisposableStack disposeStack,
    ILogManager logManager) : IStep
{
    private readonly ILogger logger = logManager.GetClassLogger<StartGrandine>();

    public Task Execute(CancellationToken cancellationToken)
    {
        string[] arguments = this.ParseArguments();

        var client = new GrandineClient(new GrandineEngineApi(this.logger, engineRpcModule));
        this.logger.Info($"Starting grandine with arguments: {string.Join(", ", arguments)}");
        client.Run(arguments);
        disposeStack.Push(client);

        return Task.CompletedTask;
    }

    private string[] ParseArguments()
    {
        var arguments = new List<string>();

        if (grandineConfig.Network == null)
        {
            arguments.Add("--network");
            arguments.Add(BlockchainIds.GetBlockchainName(chainSpec.ChainId).ToLower());
        }

        PropertyInfo[] properties = typeof(IGrandineConfig).GetProperties(BindingFlags.Public | BindingFlags.Instance);

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
                    arguments.Add(attribute.Name);
                }
            }
            else if (type == typeof(string))
            {
                arguments.Add(attribute.Name);
                arguments.Add((string)value);
            }
            else
            {
                throw new NotSupportedException($"Unrecognized option {attribute.Name} of type {prop.PropertyType}");
            }
        }

        this.logger.Debug($"Parsed grandine arguments: {string.Join(", ", arguments)}");

        return arguments.ToArray();
    }
}
