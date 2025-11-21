// Implementation of ArrayPool with exact array sizes, suggested by [@LukaszRozmej].
//
// [@LukaszRozmej]: https://github.com/LukaszRozmej

namespace Grandine.NethermindPlugin;

using System;
using System.Collections.Concurrent;

public class ExactSizeArrayPool<T>
{
    private readonly ConcurrentDictionary<int, ConcurrentBag<T[]>> pools;
    private readonly int maxArraysPerSize;

    public ExactSizeArrayPool(int maxArraysPerSize = 10)
    {
        this.pools = new ConcurrentDictionary<int, ConcurrentBag<T[]>>();
        this.maxArraysPerSize = maxArraysPerSize;
    }

    public T[] Rent(int exactSize)
    {
        if (exactSize <= 0)
        {
            throw new ArgumentException("Size must be positive", nameof(exactSize));
        }

        // GetOrAdd is thread-safe and efficient
        var pool = this.pools.GetOrAdd(exactSize, _ => new ConcurrentBag<T[]>());

        // Try to get an existing array
        if (pool.TryTake(out var array))
        {
            Array.Clear(array, 0, array.Length);
            return array;
        }

        // Create new array if none available
        return new T[exactSize];
    }

    public void Return(T[] array)
    {
        if (array == null)
        {
            throw new ArgumentNullException(nameof(array));
        }

        int size = array.Length;
        var pool = this.pools.GetOrAdd(size, _ => new ConcurrentBag<T[]>());

        // Only return if we haven't exceeded the limit
        if (pool.Count < this.maxArraysPerSize)
        {
            pool.Add(array);
        }
    }

    public void Clear()
    {
        this.pools.Clear();
    }
}