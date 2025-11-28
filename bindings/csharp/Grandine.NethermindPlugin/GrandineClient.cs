namespace Grandine.NethermindPlugin;

using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using Grandine.Native;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CPayloadStatusV1 EngineNewPayloadV1Delegate(CExecutionPayloadV1 payload);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CPayloadStatusV1 EngineNewPayloadV2Delegate(CExecutionPayloadV2 payload);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CPayloadStatusV1 EngineNewPayloadV3Delegate(CExecutionPayloadV3 payload, CVec_CH256 versionedHashes, CH256 parentBeaconBlockRoot);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CPayloadStatusV1 EngineNewPayloadV4Delegate(CExecutionPayloadV3 payload, CVec_CH256 versionedHashes, CH256 parentBeaconBlockRoot, CExecutionRequests executionRequests);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV1Delegate(CForkChoiceStateV1 state, COption_CPayloadAttributesV1 attributes);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV2Delegate(CForkChoiceStateV1 state, COption_CPayloadAttributesV2 attributes);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV3Delegate(CForkChoiceStateV1 state, COption_CPayloadAttributesV3 attributes);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CExecutionPayloadV1 EngineGetPayloadV1Delegate(CH64 payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CEngineGetPayloadV2Response EngineGetPayloadV2Delegate(CH64 payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CEngineGetPayloadV3Response EngineGetPayloadV3Delegate(CH64 payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CEngineGetPayloadV4Response EngineGetPayloadV4Delegate(CH64 payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CEngineGetPayloadV5Response EngineGetPayloadV5Delegate(CH64 payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_CVec_COption_CBlobAndProofV1 EngineGetBlobsV1Delegate(CVec_CH256 versionedHashes);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResult_COption_CVec_CBlobAndProofV2 EngineGetBlobsV2Delegate(CVec_CH256 versionedHashes);

public class GrandineClient : IAsyncDisposable
{
    private static bool initialized = false;

    private readonly EngineNewPayloadV1Delegate engineNewPayloadV1;
    private readonly EngineNewPayloadV2Delegate engineNewPayloadV2;
    private readonly EngineNewPayloadV3Delegate engineNewPayloadV3;
    private readonly EngineNewPayloadV4Delegate engineNewPayloadV4;
    private readonly EngineForkchoiceUpdatedV1Delegate engineForkchoiceUpdatedV1;
    private readonly EngineForkchoiceUpdatedV2Delegate engineForkchoiceUpdatedV2;
    private readonly EngineForkchoiceUpdatedV3Delegate engineForkchoiceUpdatedV3;
    private readonly EngineGetPayloadV1Delegate engineGetPayloadV1;
    private readonly EngineGetPayloadV2Delegate engineGetPayloadV2;
    private readonly EngineGetPayloadV3Delegate engineGetPayloadV3;
    private readonly EngineGetPayloadV4Delegate engineGetPayloadV4;
    private readonly EngineGetPayloadV5Delegate engineGetPayloadV5;
    private readonly EngineGetBlobsV1Delegate engineGetBlobsV1;
    private readonly EngineGetBlobsV2Delegate engineGetBlobsV2;

    private readonly IGrandineEngineApi engineApi;
    private Task? process;

    public GrandineClient(IGrandineEngineApi engineApi)
    {
        if (initialized)
        {
            throw new InvalidOperationException("GrandineClient is already initialized; only one instance is supported.");
        }

        this.engineApi = engineApi;

        CResult_u8 res;
        unsafe
        {
            this.engineNewPayloadV1 = this.engineApi.EngineNewPayloadV1;
            this.engineNewPayloadV2 = this.engineApi.EngineNewPayloadV2;
            this.engineNewPayloadV3 = this.engineApi.EngineNewPayloadV3;
            this.engineNewPayloadV4 = this.engineApi.EngineNewPayloadV4;
            this.engineForkchoiceUpdatedV1 = this.engineApi.EngineForkchoiceUpdatedV1;
            this.engineForkchoiceUpdatedV2 = this.engineApi.EngineForkchoiceUpdatedV2;
            this.engineForkchoiceUpdatedV3 = this.engineApi.EngineForkchoiceUpdatedV3;
            this.engineGetPayloadV1 = this.engineApi.EngineGetPayloadV1;
            this.engineGetPayloadV2 = this.engineApi.EngineGetPayloadV2;
            this.engineGetPayloadV3 = this.engineApi.EngineGetPayloadV3;
            this.engineGetPayloadV4 = this.engineApi.EngineGetPayloadV4;
            this.engineGetPayloadV5 = this.engineApi.EngineGetPayloadV5;
            this.engineGetBlobsV1 = this.engineApi.EngineGetBlobsV1;
            this.engineGetBlobsV2 = this.engineApi.EngineGetBlobsV2;
            IntPtr engine_newPayloadV1Ptr = Marshal.GetFunctionPointerForDelegate(this.engineNewPayloadV1);
            IntPtr engine_newPayloadV2Ptr = Marshal.GetFunctionPointerForDelegate(this.engineNewPayloadV2);
            IntPtr engine_newPayloadV3Ptr = Marshal.GetFunctionPointerForDelegate(this.engineNewPayloadV3);
            IntPtr engine_newPayloadV4Ptr = Marshal.GetFunctionPointerForDelegate(this.engineNewPayloadV4);
            IntPtr engine_forkchoiceUpdatedV1Ptr = Marshal.GetFunctionPointerForDelegate(this.engineForkchoiceUpdatedV1);
            IntPtr engine_forkchoiceUpdatedV2Ptr = Marshal.GetFunctionPointerForDelegate(this.engineForkchoiceUpdatedV2);
            IntPtr engine_forkchoiceUpdatedV3Ptr = Marshal.GetFunctionPointerForDelegate(this.engineForkchoiceUpdatedV3);
            IntPtr engine_getPayloadV1Ptr = Marshal.GetFunctionPointerForDelegate(this.engineGetPayloadV1);
            IntPtr engine_getPayloadV2Ptr = Marshal.GetFunctionPointerForDelegate(this.engineGetPayloadV2);
            IntPtr engine_getPayloadV3Ptr = Marshal.GetFunctionPointerForDelegate(this.engineGetPayloadV3);
            IntPtr engine_getPayloadV4Ptr = Marshal.GetFunctionPointerForDelegate(this.engineGetPayloadV4);
            IntPtr engine_getPayloadV5Ptr = Marshal.GetFunctionPointerForDelegate(this.engineGetPayloadV5);
            IntPtr engine_getBlobsV1Ptr = Marshal.GetFunctionPointerForDelegate(this.engineGetBlobsV1);
            IntPtr engine_getBlobsV2Ptr = Marshal.GetFunctionPointerForDelegate(this.engineGetBlobsV2);
            res = NativeMethods.grandine_set_execution_layer_adapter(new CEmbedAdapter
            {
                engine_new_payload_v1 = (delegate* unmanaged[Cdecl]<CExecutionPayloadV1, CResult_CPayloadStatusV1>)engine_newPayloadV1Ptr,
                engine_new_payload_v2 = (delegate* unmanaged[Cdecl]<CExecutionPayloadV2, CResult_CPayloadStatusV1>)engine_newPayloadV2Ptr,
                engine_new_payload_v3 = (delegate* unmanaged[Cdecl]<CExecutionPayloadV3, CVec_CH256, CH256, CResult_CPayloadStatusV1>)engine_newPayloadV3Ptr,
                engine_new_payload_v4 = (delegate* unmanaged[Cdecl]<CExecutionPayloadV3, CVec_CH256, CH256, CExecutionRequests, CResult_CPayloadStatusV1>)engine_newPayloadV4Ptr,
                engine_forkchoice_updated_v1 = (delegate* unmanaged[Cdecl]<CForkChoiceStateV1, COption_CPayloadAttributesV1, CResult_CForkChoiceUpdatedResponse>)engine_forkchoiceUpdatedV1Ptr,
                engine_forkchoice_updated_v2 = (delegate* unmanaged[Cdecl]<CForkChoiceStateV1, COption_CPayloadAttributesV2, CResult_CForkChoiceUpdatedResponse>)engine_forkchoiceUpdatedV2Ptr,
                engine_forkchoice_updated_v3 = (delegate* unmanaged[Cdecl]<CForkChoiceStateV1, COption_CPayloadAttributesV3, CResult_CForkChoiceUpdatedResponse>)engine_forkchoiceUpdatedV3Ptr,
                engine_get_payload_v1 = (delegate* unmanaged[Cdecl]<CH64, CResult_CExecutionPayloadV1>)engine_getPayloadV1Ptr,
                engine_get_payload_v2 = (delegate* unmanaged[Cdecl]<CH64, CResult_CEngineGetPayloadV2Response>)engine_getPayloadV2Ptr,
                engine_get_payload_v3 = (delegate* unmanaged[Cdecl]<CH64, CResult_CEngineGetPayloadV3Response>)engine_getPayloadV3Ptr,
                engine_get_payload_v4 = (delegate* unmanaged[Cdecl]<CH64, CResult_CEngineGetPayloadV4Response>)engine_getPayloadV4Ptr,
                engine_get_payload_v5 = (delegate* unmanaged[Cdecl]<CH64, CResult_CEngineGetPayloadV5Response>)engine_getPayloadV5Ptr,
                engine_get_blobs_v1 = (delegate* unmanaged[Cdecl]<CVec_CH256, CResult_CVec_COption_CBlobAndProofV1>)engine_getBlobsV1Ptr,
                engine_get_blobs_v2 = (delegate* unmanaged[Cdecl]<CVec_CH256, CResult_COption_CVec_CBlobAndProofV2>)engine_getBlobsV2Ptr,
            });
        }

        if (res.code != NativeMethods.GRANDINE_SUCCESS)
        {
            throw new GrandineInitializationException(res.code, res.message);
        }

        initialized = true;
    }

    public ValueTask DisposeAsync()
    {
        this.Shutdown();

        return new ValueTask(Task.Run(
            async () =>
            {
                if (this.process != null)
                {
                    await this.process;
                }
            }));
    }

    public void Run(string[] args)
    {
        IntPtr convArgs = Marshal.AllocHGlobal(
            args.Length * IntPtr.Size);

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            byte[] strBytes = Encoding.ASCII.GetBytes(arg + '\0');
            IntPtr bytesPtr = Marshal.AllocHGlobal(strBytes.Length);
            Marshal.Copy(strBytes, 0, bytesPtr, strBytes.Length);
            Marshal.WriteIntPtr(
                convArgs,
                i * IntPtr.Size,
                bytesPtr);
        }

        this.process = Task.Run(() =>
        {
            unsafe
            {
                NativeMethods.grandine_run((ulong)args.Length, (byte**)convArgs);
            }
        });
    }

    public void Shutdown()
    {
        unsafe
        {
            NativeMethods.grandine_shutdown();
        }
    }
}