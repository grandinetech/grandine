namespace Grandine.test;

public class Tests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void Test1()
    {
        Grandine grandine = new();
        grandine.Run();
        Assert.Pass();
    }
}