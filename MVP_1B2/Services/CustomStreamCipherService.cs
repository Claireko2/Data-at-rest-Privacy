using System.Numerics;
using System.Security.Cryptography;

namespace MVP_1B2.Services
{
    public sealed class CustomStreamCipherService
    {
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int BlockSize = 64;
        private const int BufferSize = 64 * 1024;
        private const int TagSize = 16;
        private const int HeaderSize = 4 + NonceSize;

        private static readonly byte[] FileMagic =
            new byte[]
            {
            (byte)'M',
            (byte)'V',
            (byte)'P',
            (byte)'1'
            };

        private readonly byte[] _key;

        public CustomStreamCipherService(IConfiguration configuration)
        {
            var keyBase64 =
                configuration["StreamCipher:Key"];

            if (string.IsNullOrWhiteSpace(keyBase64))
            {
                throw new InvalidOperationException(
                    "StreamCipher:Key is not configured.");
            }

            try
            {
                _key = Convert.FromBase64String(keyBase64);
            }
            catch (FormatException)
            {
                throw new InvalidOperationException(
                    "StreamCipher:Key is not valid Base64.");
            }

            if (_key.Length != KeySize)
            {
                throw new InvalidOperationException(
                    "StreamCipher:Key must contain exactly 32 bytes.");
            }
        }
        private static byte[] GenerateNonce()
        {
            return RandomNumberGenerator.GetBytes(NonceSize);
        }
        private static void QuarterRound(
            ref uint a,
            ref uint b,
            ref uint c,
            ref uint d)
        {
            a += b;
            d ^= a;
            d = BitOperations.RotateLeft(d, 16);

            c += d;
            b ^= c;
            b = BitOperations.RotateLeft(b, 12);

            a += b;
            d ^= a;
            d = BitOperations.RotateLeft(d, 8);

            c += d;
            b ^= c;
            b = BitOperations.RotateLeft(b, 7);
        }
        private static uint LoadUInt32(
            byte[] buffer,
            int offset)
        {
            return
                (uint)buffer[offset]
                | ((uint)buffer[offset + 1] << 8)
                | ((uint)buffer[offset + 2] << 16)
                | ((uint)buffer[offset + 3] << 24);
        }
        private static void StoreUInt32(
            byte[] buffer,
            int offset,
            uint value)
        {
            buffer[offset] =
                (byte)value;

            buffer[offset + 1] =
                (byte)(value >> 8);

            buffer[offset + 2] =
                (byte)(value >> 16);

            buffer[offset + 3] =
                (byte)(value >> 24);
        }
        private uint[] CreateState(
            byte[] nonce,
            uint counter)
        {
            uint[] state = new uint[16];

            // Fixed constants
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            // 256-bit key
            for (int i = 0; i < 8; i++)
            {
                state[4 + i] =
                    LoadUInt32(_key, i * 4);
            }

            // Counter
            state[12] = counter;

            // 96-bit nonce
            for (int i = 0; i < 3; i++)
            {
                state[13 + i] =
                    LoadUInt32(nonce, i * 4);
            }

            return state;
        }
        private byte[] GenerateKeystreamBlock(
            byte[] nonce,
            uint counter)
        {
            uint[] state =
                CreateState(nonce, counter);

            uint[] working =
                (uint[])state.Clone();

            for (int round = 0; round < 10; round++)
            {
                // Phase 1: column-style mixing

                QuarterRound(
                    ref working[0],
                    ref working[4],
                    ref working[8],
                    ref working[12]);

                QuarterRound(
                    ref working[1],
                    ref working[5],
                    ref working[9],
                    ref working[13]);

                QuarterRound(
                    ref working[2],
                    ref working[6],
                    ref working[10],
                    ref working[14]);

                QuarterRound(
                    ref working[3],
                    ref working[7],
                    ref working[11],
                    ref working[15]);


                // Phase 2: diagonal-style mixing

                QuarterRound(
                    ref working[0],
                    ref working[5],
                    ref working[10],
                    ref working[15]);

                QuarterRound(
                    ref working[1],
                    ref working[6],
                    ref working[11],
                    ref working[12]);

                QuarterRound(
                    ref working[2],
                    ref working[7],
                    ref working[8],
                    ref working[13]);

                QuarterRound(
                    ref working[3],
                    ref working[4],
                    ref working[9],
                    ref working[14]);
            }

            // Feed-forward
            for (int i = 0; i < 16; i++)
            {
                working[i] += state[i];
            }

            byte[] output =
                new byte[BlockSize];

            for (int i = 0; i < 16; i++)
            {
                StoreUInt32(
                    output,
                    i * 4,
                    working[i]);
            }

            return output;
        }
  
        public byte[] Transform(
            byte[] data,
            byte[] nonce,
            uint startingCounter = 0)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != NonceSize)
                throw new ArgumentException(
                    "Nonce must be exactly 12 bytes.");

            byte[] result =
                new byte[data.Length];

            int offset = 0;
            uint counter = startingCounter;

            while (offset < data.Length)
            {
                byte[] keystream =
                    GenerateKeystreamBlock(
                        nonce,
                        counter);

                int remaining =
                    data.Length - offset;

                int length =
                    Math.Min(BlockSize, remaining);

                for (int i = 0; i < length; i++)
                {
                    result[offset + i] =
                        (byte)(
                            data[offset + i]
                            ^ keystream[i]);
                }

                offset += length;
                counter++;
            }

            return result;
        }
        public async Task EncryptFileAsync(
            string inputPath,
            string outputPath)
        {
            if (string.IsNullOrWhiteSpace(inputPath))
                throw new ArgumentException(
                    "Input path is required.",
                    nameof(inputPath));

            if (string.IsNullOrWhiteSpace(outputPath))
                throw new ArgumentException(
                    "Output path is required.",
                    nameof(outputPath));

            if (!File.Exists(inputPath))
                throw new FileNotFoundException(
                    "Input file was not found.",
                    inputPath);

            // Generate a new random nonce for this file.
            byte[] nonce = GenerateNonce();

            await using FileStream input =
                new FileStream(
                    inputPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    BufferSize,
                    useAsync: true);

            await using FileStream output =
                new FileStream(
                    outputPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    BufferSize,
                    useAsync: true);

            // -------------------------------------------------
            // Write file header
            // -------------------------------------------------

            await output.WriteAsync(FileMagic);

            await output.WriteAsync(nonce);

            // -------------------------------------------------
            // Initialize custom integrity tag
            // -------------------------------------------------

            uint[] tagState =
                CreateTagState(nonce);

            uint tagBlockCounter = 0;

            long totalCiphertextLength = 0;

            // -------------------------------------------------
            // Encrypt file contents
            // -------------------------------------------------

            byte[] buffer =
                new byte[BufferSize];

            byte[] encryptedBuffer =
                new byte[BufferSize];

            int bytesRead;

            uint counter = 0;

            while ((bytesRead =
                await input.ReadAsync(
                    buffer.AsMemory(0, BufferSize))) > 0)
            {
                int bufferOffset = 0;

                while (bufferOffset < bytesRead)
                {
                    byte[] keystream =
                        GenerateKeystreamBlock(
                            nonce,
                            counter);

                    int remaining =
                        bytesRead - bufferOffset;

                    int length =
                        Math.Min(
                            BlockSize,
                            remaining);

                    for (int i = 0; i < length; i++)
                    {
                        encryptedBuffer[bufferOffset + i] =
                            (byte)(
                                buffer[bufferOffset + i]
                                ^ keystream[i]);
                    }

                    bufferOffset += length;

                    counter++;
                }

                // -------------------------------------------------
                // Update integrity tag using ciphertext
                // -------------------------------------------------

                UpdateTagState(
                    tagState,
                    encryptedBuffer,
                    0,
                    bytesRead,
                    ref tagBlockCounter);

                totalCiphertextLength += bytesRead;

                // -------------------------------------------------
                // Write ciphertext
                // -------------------------------------------------

                await output.WriteAsync(
                    encryptedBuffer.AsMemory(
                        0,
                        bytesRead));
            }

            // -------------------------------------------------
            // Finalize integrity tag
            // -------------------------------------------------

            byte[] tag =
                FinalizeTag(
                    tagState,
                    totalCiphertextLength);

            // -------------------------------------------------
            // Append tag to the encrypted file
            // -------------------------------------------------

            await output.WriteAsync(tag);
        }
        public async Task DecryptFileAsync(
           string inputPath,
           string outputPath)
        {
            if (string.IsNullOrWhiteSpace(inputPath))
                throw new ArgumentException(
                    "Input path is required.",
                    nameof(inputPath));

            if (string.IsNullOrWhiteSpace(outputPath))
                throw new ArgumentException(
                    "Output path is required.",
                    nameof(outputPath));

            if (!File.Exists(inputPath))
                throw new FileNotFoundException(
                    "Encrypted file was not found.",
                    inputPath);

            await using FileStream input =
                new FileStream(
                    inputPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    BufferSize,
                    useAsync: true);

            // -------------------------------------------------
            // Minimum file size:
            //
            // Magic   = 4 bytes
            // Nonce   = 12 bytes
            // Tag     = 16 bytes
            //
            // Total   = 32 bytes
            // -------------------------------------------------

         

            if (input.Length <
                HeaderSize + TagSize)
            {
                throw new InvalidDataException(
                    "The encrypted file is too small.");
            }

            // -------------------------------------------------
            // Read and verify file magic
            // -------------------------------------------------

            byte[] magic =
                new byte[FileMagic.Length];

            int magicBytesRead =
                await input.ReadAsync(
                    magic.AsMemory());

            if (magicBytesRead !=
                FileMagic.Length ||
                !magic.SequenceEqual(FileMagic))
            {
                throw new InvalidDataException(
                    "The file is not a valid MVP1 encrypted file.");
            }

            // -------------------------------------------------
            // Read nonce
            // -------------------------------------------------

            byte[] nonce =
                new byte[NonceSize];

            int nonceBytesRead =
                await input.ReadAsync(
                    nonce.AsMemory());

            if (nonceBytesRead != NonceSize)
            {
                throw new InvalidDataException(
                    "The encrypted file does not contain a valid nonce.");
            }

            // -------------------------------------------------
            // Determine ciphertext length
            // -------------------------------------------------

            long ciphertextLength =
                input.Length
                - HeaderSize
                - TagSize;

            if (ciphertextLength < 0)
            {
                throw new InvalidDataException(
                    "Invalid encrypted file format.");
            }

            // -------------------------------------------------
            // First pass:
            // Calculate the expected authentication tag.
            // -------------------------------------------------

            uint[] tagState =
                CreateTagState(nonce);

            uint tagBlockCounter = 0;

            long remainingCiphertext =
                ciphertextLength;

            byte[] tagBuffer =
                new byte[BufferSize];

            while (remainingCiphertext > 0)
            {
                int bytesToRead =
                    (int)Math.Min(
                        BufferSize,
                        remainingCiphertext);

                int bytesRead =
                    await input.ReadAsync(
                        tagBuffer.AsMemory(
                            0,
                            bytesToRead));

                if (bytesRead != bytesToRead)
                {
                    throw new InvalidDataException(
                        "Unexpected end of encrypted file.");
                }

                UpdateTagState(
                    tagState,
                    tagBuffer,
                    0,
                    bytesRead,
                    ref tagBlockCounter);

                remainingCiphertext -= bytesRead;
            }

            // -------------------------------------------------
            // Read stored authentication tag
            // -------------------------------------------------

            byte[] storedTag =
                new byte[TagSize];

            int tagBytesRead =
                await input.ReadAsync(
                    storedTag.AsMemory());

            if (tagBytesRead != TagSize)
            {
                throw new InvalidDataException(
                    "The encrypted file does not contain a valid authentication tag.");
            }

            // -------------------------------------------------
            // Calculate expected tag
            // -------------------------------------------------

            byte[] expectedTag =
                FinalizeTag(
                    tagState,
                    ciphertextLength);

            // -------------------------------------------------
            // Compare tags
            // -------------------------------------------------

            int difference = 0;

            for (int i = 0; i < TagSize; i++)
            {
                difference |=
                    expectedTag[i] ^ storedTag[i];
            }

            if (difference != 0)
            {
                throw new CryptographicException(
                    "Integrity verification failed. " +
                    "The encrypted file may have been modified.");
            }

            // -------------------------------------------------
            // Second pass:
            // Decrypt only after integrity verification succeeds.
            // -------------------------------------------------

            input.Position = HeaderSize;

            await using FileStream output =
                new FileStream(
                    outputPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    BufferSize,
                    useAsync: true);

            byte[] buffer =
                new byte[BufferSize];

            byte[] decryptedBuffer =
                new byte[BufferSize];

            long remainingToDecrypt =
                ciphertextLength;

            uint counter = 0;

            while (remainingToDecrypt > 0)
            {
                int bytesToRead =
                    (int)Math.Min(
                        BufferSize,
                        remainingToDecrypt);

                int bytesRead =
                    await input.ReadAsync(
                        buffer.AsMemory(
                            0,
                            bytesToRead));

                if (bytesRead != bytesToRead)
                {
                    throw new InvalidDataException(
                        "Unexpected end of encrypted file.");
                }

                int bufferOffset = 0;

                while (bufferOffset < bytesRead)
                {
                    byte[] keystream =
                        GenerateKeystreamBlock(
                            nonce,
                            counter);

                    int remaining =
                        bytesRead - bufferOffset;

                    int length =
                        Math.Min(
                            BlockSize,
                            remaining);

                    for (int i = 0; i < length; i++)
                    {
                        decryptedBuffer[bufferOffset + i] =
                            (byte)(
                                buffer[bufferOffset + i]
                                ^ keystream[i]);
                    }

                    bufferOffset += length;

                    counter++;
                }

                await output.WriteAsync(
                    decryptedBuffer.AsMemory(
                        0,
                        bytesRead));

                remainingToDecrypt -= bytesRead;
            }
        }
        private uint[] CreateTagState(byte[] nonce)
        {
            uint[] state = new uint[16];

            // Custom tag initialization constants
            state[0] = 0x4D565031; // "MVP1"
            state[1] = 0xA3B1BAC6;
            state[2] = 0x56AA3350;
            state[3] = 0x677D9197;

            // 256-bit key
            for (int i = 0; i < 8; i++)
            {
                state[4 + i] =
                    LoadUInt32(_key, i * 4);
            }

            // 96-bit nonce
            for (int i = 0; i < 3; i++)
            {
                state[12 + i] =
                    LoadUInt32(nonce, i * 4);
            }

            // Block counter
            state[15] = 0;

            return state;
        }
        private void UpdateTagState(
    uint[] state,
    byte[] buffer,
    int offset,
    int length,
    ref uint blockCounter)
        {
            int processed = 0;

            while (processed < length)
            {
                int blockLength =
                    Math.Min(
                        BlockSize,
                        length - processed);

                // Temporary 64-byte block.
                // Zero padding is used for a partial final block.
                byte[] block = new byte[BlockSize];

                Array.Copy(
                    buffer,
                    offset + processed,
                    block,
                    0,
                    blockLength);

                // Absorb the ciphertext block into the tag state.
                for (int i = 0; i < 16; i++)
                {
                    uint blockWord =
                        LoadUInt32(
                            block,
                            i * 4);

                    state[i] ^= blockWord;
                }

                // Add the block counter so that
                // identical blocks at different positions
                // affect the tag differently.
                state[15] ^= blockCounter;

                // Custom ARX mixing.
                for (int round = 0; round < 4; round++)
                {
                    // Column-style mixing
                    QuarterRound(
                        ref state[0],
                        ref state[4],
                        ref state[8],
                        ref state[12]);

                    QuarterRound(
                        ref state[1],
                        ref state[5],
                        ref state[9],
                        ref state[13]);

                    QuarterRound(
                        ref state[2],
                        ref state[6],
                        ref state[10],
                        ref state[14]);

                    QuarterRound(
                        ref state[3],
                        ref state[7],
                        ref state[11],
                        ref state[15]);

                    // Diagonal-style mixing
                    QuarterRound(
                        ref state[0],
                        ref state[5],
                        ref state[10],
                        ref state[15]);

                    QuarterRound(
                        ref state[1],
                        ref state[6],
                        ref state[11],
                        ref state[12]);

                    QuarterRound(
                        ref state[2],
                        ref state[7],
                        ref state[8],
                        ref state[13]);

                    QuarterRound(
                        ref state[3],
                        ref state[4],
                        ref state[9],
                        ref state[14]);
                }

                blockCounter++;
                processed += blockLength;
            }
        }
        private byte[] FinalizeTag(
    uint[] state,
    long totalLength)
        {
            // Mix the total ciphertext length into the state.
            uint lowLength =
                (uint)(totalLength & 0xFFFFFFFF);

            uint highLength =
                (uint)((ulong)totalLength >> 32);

            state[14] ^= lowLength;
            state[15] ^= highLength;

            // Final ARX mixing.
            for (int round = 0; round < 4; round++)
            {
                // Column-style mixing
                QuarterRound(
                    ref state[0],
                    ref state[4],
                    ref state[8],
                    ref state[12]);

                QuarterRound(
                    ref state[1],
                    ref state[5],
                    ref state[9],
                    ref state[13]);

                QuarterRound(
                    ref state[2],
                    ref state[6],
                    ref state[10],
                    ref state[14]);

                QuarterRound(
                    ref state[3],
                    ref state[7],
                    ref state[11],
                    ref state[15]);

                // Diagonal-style mixing
                QuarterRound(
                    ref state[0],
                    ref state[5],
                    ref state[10],
                    ref state[15]);

                QuarterRound(
                    ref state[1],
                    ref state[6],
                    ref state[11],
                    ref state[12]);

                QuarterRound(
                    ref state[2],
                    ref state[7],
                    ref state[8],
                    ref state[13]);

                QuarterRound(
                    ref state[3],
                    ref state[4],
                    ref state[9],
                    ref state[14]);
            }

            // Produce a 128-bit (16-byte) tag.
            byte[] tag = new byte[TagSize];

            for (int i = 0; i < 4; i++)
            {
                StoreUInt32(
                    tag,
                    i * 4,
                    state[i]);
            }

            return tag;
        }
        
    }
}