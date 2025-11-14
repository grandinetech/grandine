using System;

namespace Grandine.NethermindPlugin;

public class GrandineConfigItemAttribute : Attribute
{
    public required string Name { get; set; }
}
