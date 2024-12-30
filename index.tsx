import React, { useState } from 'react';
import { Buffer } from 'buffer';
import { Box, Button, CircularProgress, Paper, TextField, Typography } from '@mui/material';
import { subtle } from 'crypto';

interface EncryptionProps {
    recipientPublicKey: string;
    apiEndpoint: string;
}

export const FileEncryption: React.FC<EncryptionProps> = ({ recipientPublicKey, apiEndpoint }) => {
    const [file, setFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const [uploadUrl, setUploadUrl] = useState<string>('');

    const generateAESKey = async () => {
        const key = await subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
        return key;
    };

    const encryptFile = async (fileData: ArrayBuffer, symmetricKey: CryptoKey) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedContent = await subtle.encrypt(
            {
                name: 'AES-GCM',
                iv
            },
            symmetricKey,
            fileData
        );

        return {
            iv: Buffer.from(iv).toString('base64'),
            encryptedData: Buffer.from(encryptedContent).toString('base64')
        };
    };

    const encryptSymmetricKey = async (symmetricKey: CryptoKey, publicKey: string) => {
        const importedPublicKey = await subtle.importKey(
            'spki',
            Buffer.from(publicKey, 'base64'),
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['encrypt']
        );

        const exportedSymmetricKey = await subtle.exportKey('raw', symmetricKey);
        const encryptedSymmetricKey = await subtle.encrypt(
            {
                name: 'RSA-OAEP'
            },
            importedPublicKey,
            exportedSymmetricKey
        );

        return Buffer.from(encryptedSymmetricKey).toString('base64');
    };

    const handleUpload = async () => {
        if (!file) return;

        try {
            setLoading(true);
            const fileData = await file.arrayBuffer();

            // Generate symmetric key
            const symmetricKey = await generateAESKey();

            // Encrypt file
            const { iv, encryptedData } = await encryptFile(fileData, symmetricKey);

            // Encrypt symmetric key
            const encryptedSymmetricKey = await encryptSymmetricKey(symmetricKey, recipientPublicKey);

            // Upload to API
            const response = await fetch(`${apiEndpoint}/upload`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    encryptedData,
                    iv,
                    encryptedSymmetricKey,
                    fileName: file.name,
                    recipientPublicKey
                })
            });

            const { downloadUrl } = await response.json();
            setUploadUrl(downloadUrl);
        } catch (error) {
            console.error('Upload failed:', error);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Paper elevation={3} sx={{ p: 3, maxWidth: 600, mx: 'auto', mt: 4 }}>
    <Typography variant="h5" gutterBottom>
    Secure File Upload
    </Typography>

    <Box sx={{ my: 2 }}>
    <input
        type="file"
    onChange={(e) => setFile(e.target.files?.[0] || null)}
    style={{ display: 'none' }}
    id="file-input"
    />
    <label htmlFor="file-input">
    <Button variant="contained" component="span">
        Select File
    </Button>
    </label>
    {file && (
        <Typography sx={{ mt: 1 }}>
        Selected: {file.name}
        </Typography>
    )}
    </Box>

    <Button
    variant="contained"
    color="primary"
    onClick={handleUpload}
    disabled={!file || loading}
    sx={{ mt: 2 }}
>
    {loading ? <CircularProgress size={24} /> : 'Upload'}
        </Button>

        {uploadUrl && (
            <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle1">Share this URL with the recipient:</Typography>
        <TextField
            fullWidth
            value={uploadUrl}
            variant="outlined"
            size="small"
            InputProps={{
            readOnly: true
        }}
            />
            </Box>
        )}
        </Paper>
    );
    };