## Metrics

### Beacon Node metrics

Grandine provides a set of Beacon Node metrics that are suitable to be consumed by [Prometheus](https://github.com/prometheus/prometheus) and visualized via [Grafana](https://github.com/grafana/grafana) dashboards. 

### Remote Metrics 

Grandine can to push metrics to a remote endpoint every 60 seconds. This option is useful for services such as [beaconcha.in](https://kb.beaconcha.in/beaconcha.in-explorer/mobile-app-less-than-greater-than-beacon-node).

### Relevant command line options:

* `--metrics` - enables metrics (default: disabled);
* `--metrics-address` - address for metrics endpoint (default: `127.0.0.1`);
* `--metrics-port` - port for metrics endpoint (default: `5054`);
* `--remote-metrics-url` - remote metrics URL that Grandine will periodically send metrics to (default: disabled).
