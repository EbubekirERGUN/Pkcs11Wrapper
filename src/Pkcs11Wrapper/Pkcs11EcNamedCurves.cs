namespace Pkcs11Wrapper;

public static class Pkcs11EcNamedCurves
{
    public static byte[] Prime256v1Parameters => [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    public static byte[] P256Parameters => Prime256v1Parameters;

    public static byte[] DecodeEcPointAttribute(ReadOnlySpan<byte> encodedPoint)
    {
        if (encodedPoint.Length < 2 || encodedPoint[0] != 0x04)
        {
            throw new ArgumentException("CKA_EC_POINT must be a DER OCTET STRING.", nameof(encodedPoint));
        }

        int lengthOffset = 1;
        int contentLength;

        if ((encodedPoint[lengthOffset] & 0x80) == 0)
        {
            contentLength = encodedPoint[lengthOffset];
            lengthOffset++;
        }
        else
        {
            int lengthByteCount = encodedPoint[lengthOffset] & 0x7F;
            lengthOffset++;

            if (lengthByteCount is 0 or > 4 || encodedPoint.Length < lengthOffset + lengthByteCount)
            {
                throw new ArgumentException("CKA_EC_POINT contains an invalid DER length.", nameof(encodedPoint));
            }

            contentLength = 0;
            for (int i = 0; i < lengthByteCount; i++)
            {
                contentLength = (contentLength << 8) | encodedPoint[lengthOffset + i];
            }

            lengthOffset += lengthByteCount;
        }

        if (contentLength < 0 || encodedPoint.Length != lengthOffset + contentLength)
        {
            throw new ArgumentException("CKA_EC_POINT length does not match the DER payload.", nameof(encodedPoint));
        }

        return encodedPoint[lengthOffset..].ToArray();
    }
}
