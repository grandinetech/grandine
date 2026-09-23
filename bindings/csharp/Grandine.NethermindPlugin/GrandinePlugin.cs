namespace Grandine.NethermindPlugin;

using Autofac;
using Autofac.Core;

using Nethermind.Api.Extensions;
using Nethermind.Api.Steps;

public class GrandinePlugin(IGrandineConfig grandineConfig) : INethermindPlugin
{
    public string Name => "Grandine plugin";

    public string Description => "Nethermind plugin to enable embedded grandine CL client";

    public string Author => "Grandine team";

    public bool Enabled => grandineConfig.Enabled;

    public IModule Module => new GrandinePluginModule();
}

public class GrandinePluginModule : Module
{
    protected override void Load(ContainerBuilder builder)
    {
        base.Load(builder);

        builder.AddStep(typeof(StartGrandine));
    }
}
