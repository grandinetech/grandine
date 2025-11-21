namespace Grandine.NethermindPlugin;

public class GrandineConfigItemAttribute : Attribute
{
    required public string Name { get; set; }
}