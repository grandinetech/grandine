// SPDX-FileCopyrightText: 2024 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Autofac;
using Nethermind.Api;
using Nethermind.Api.Extensions;
using Nethermind.Core;
using Nethermind.Core.Authentication;
using Nethermind.Core.Timers;
using Nethermind.JsonRpc;
using Nethermind.Logging;
using Nethermind.Merge.Plugin;
using Grandine.Bindings;
using Nethermind.Api.Steps;
using Nethermind.Consensus;
using Nethermind.Consensus.Producers;
using Nethermind.Consensus.Transactions;
using Nethermind.Merge.Plugin.BlockProduction;
using Nethermind.Merge.Plugin.GC;
using Nethermind.Merge.Plugin.Handlers;
using Nethermind.JsonRpc.Modules;
using Nethermind.Config;
using Nethermind.Blockchain.Synchronization;
using Nethermind.Merge.Plugin.InvalidChainTracker;
using Nethermind.Blockchain;
using Nethermind.Blockchain.Receipts;
using Nethermind.Consensus.Rewards;
using Nethermind.Consensus.Validators;
using Nethermind.Facade.Eth.RpcTransaction;
using Nethermind.Merge.Plugin.Synchronization;
using Nethermind.HealthChecks;
using Nethermind.Init.Steps;
using Nethermind.Specs.ChainSpecStyle;
using Nethermind.Blockchain.Find;
using Nethermind.JsonRpc.Modules.Eth;

namespace Grandine.Bindings;

public class GrandinePlugin(IGrandineConfig grandineConfig) : INethermindPlugin
{
    public string Name => "Grandine plugin";
    public string Description => "Nethermind plugin to enable embedded grandine CL client";
    public string Author => "Grandine team";

    private ILogger _logger;
    private INethermindApi _api;

    public bool Enabled => grandineConfig.Enabled;

    private List<string> _arguments = new List<string>();

    public Task Init(INethermindApi nethermindApi)
    {
        _api = nethermindApi;
        _logger = nethermindApi.LogManager.GetClassLogger();
        _logger.Warn("Initializing grandine plugin...");

        Type configType = grandineConfig.GetType();

        var rpcConfig = nethermindApi.Config<IJsonRpcConfig>();

        PropertyInfo[] properties = configType.GetInterface("IGrandineConfig").GetProperties(BindingFlags.Public | BindingFlags.Instance);

        if (grandineConfig.Network == null)
        {
            (IApiWithStores getFromApi, _) = nethermindApi.ForInit;
            _arguments.Add("--network");
            _arguments.Add(BlockchainIds.GetBlockchainName(getFromApi.ChainSpec.ChainId).ToLower());
        }

        foreach (PropertyInfo prop in properties)
        {
            GrandineConfigItemAttribute attribute = prop.GetCustomAttribute<GrandineConfigItemAttribute>();

            if (attribute == null)
            {
                continue;
            }

            object value = prop.GetValue(grandineConfig);

            if (value == null)
            {
                continue;
            }

            if (prop.PropertyType == typeof(bool) && (bool)value)
            {
                _arguments.Add(attribute.Name);
            }
            else if (prop.PropertyType == typeof(string))
            {
                _arguments.Add(attribute.Name);
                _arguments.Add((string)value);
            }
            else if (prop.PropertyType.IsArray)
            {
                var elementType = prop.PropertyType.GetElementType();
                if (elementType == typeof(string))
                {
                    var values = (string[])value;

                    foreach (var val in values)
                    {
                        _arguments.Add(attribute.Name);
                        _arguments.Add(val);
                    }
                }
            }
        }

        _logger.Warn($"Starting grandine with arguments: {string.Join(", ", _arguments)}");

        return Task.CompletedTask;
    }

    public Task InitRpcModules()
    {
        _logger.Warn("Initializing grandine RPC...");
        if (_api is null)
            return Task.CompletedTask;

        IEngineRpcModule engineRpcModule = _api.Context.Resolve<IEngineRpcModule>();

        var api = new GrandineEngineApi(_logger, engineRpcModule);
        Task task = new Task(() =>
        {
            try
            {
                var client = new GrandineClient(api.getAdapter());
                client.Run(_arguments.ToArray());
            }
            catch (Exception e)
            {
                _logger.Error($"Failed to start grandine: {e}");
            }
        });
        task.Start();
        return task;
    }

    public ValueTask DisposeAsync() { return ValueTask.CompletedTask; }
}
