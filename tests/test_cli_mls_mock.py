import unittest
import sys
from unittest.mock import patch, MagicMock
import base64
import json
from pathlib import Path
from typer.testing import CliRunner
from cli.transfers.commands import app
from cli.users.commands import app as users_app

runner = CliRunner()

class TestCLIMLS(unittest.TestCase):
    
    def setUp(self):
        self.token = "fake_session_token"
        self.mls_token_payload = {
            "clearance": "SECRET",
            "departments": ["HR", "Engineering"],
            "exp": 9999999999
        }
        self.mls_token = "header." + base64.urlsafe_b64encode(json.dumps(self.mls_token_payload).encode()).decode() + ".sig"

    @patch("cli.transfers.commands.load_token")
    @patch("cli.transfers.commands.load_mls_token")
    @patch("cli.transfers.commands.api_upload_transfer")
    @patch("cli.transfers.commands.api_get_user_public_key")
    @patch("cli.transfers.commands.encrypt_file_key_for_user")
    def test_upload_mls_success(self, mock_encrypt_key, mock_get_key, mock_upload, mock_load_mls, mock_load_token):
        mock_load_token.return_value = self.token
        mock_load_mls.return_value = self.mls_token
        mock_get_key.return_value = "fake_pem"
        mock_encrypt_key.return_value = b"encrypted_key"
        mock_upload.return_value = "fake_transfer_id"
        
        # Create dummy file
        with open("test_file.txt", "w") as f:
            f.write("content")
            
        # Try upload with valid level (SECRET <= SECRET) and valid dept (HR subset)
        result = runner.invoke(app, ["upload", "test_file.txt", "--to", "user2", "--level", "SECRET", "--dept", "HR"])
        if result.exit_code != 0:
            print(result.stdout, file=sys.stderr)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Transferência enviada com sucesso", result.stdout)
        
        # Verify API call args
        args, kwargs = mock_upload.call_args
        transfer_data = args[1]
        self.assertEqual(transfer_data["classification"]["level"], "SECRET")
        self.assertEqual(transfer_data["classification"]["departments"], ["HR"])
        self.assertEqual(kwargs["mls_token"], self.mls_token)

        Path("test_file.txt").unlink()

    @patch("cli.transfers.commands.load_token")
    @patch("cli.transfers.commands.load_mls_token")
    def test_upload_mls_fail_write_down(self, mock_load_mls, mock_load_token):
        mock_load_token.return_value = self.token
        mock_load_mls.return_value = self.mls_token
        
        with open("test_file.txt", "w") as f:
            f.write("content")
            
        # Try upload with higher level (TOP_SECRET > SECRET) -> Should Fail?
        # Wait, rule is: User Level <= File Level.
        # So if User is SECRET, File is TOP_SECRET -> OK (Write Up).
        # If User is SECRET, File is CONFIDENTIAL -> FAIL (Write Down).
        
        # Test Write Down Violation: File Level (CONFIDENTIAL) < User Level (SECRET)
        result = runner.invoke(app, ["upload", "test_file.txt", "--to", "user2", "--level", "CONFIDENTIAL"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Erro MLS", result.stdout)
        self.assertIn("User Level <= File Level", result.stdout)
        
        Path("test_file.txt").unlink()

    @patch("cli.transfers.commands.load_token")
    @patch("cli.transfers.commands.load_mls_token")
    def test_upload_mls_fail_dept(self, mock_load_mls, mock_load_token):
        mock_load_token.return_value = self.token
        mock_load_mls.return_value = self.mls_token
        
        with open("test_file.txt", "w") as f:
            f.write("content")
            
        # Try upload with department not in user list (Finance not in [HR, Engineering])
        result = runner.invoke(app, ["upload", "test_file.txt", "--to", "user2", "--level", "SECRET", "--dept", "Finance"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Erro MLS", result.stdout)
        self.assertIn("Não tens acesso aos departamentos", result.stdout)
        
        Path("test_file.txt").unlink()

    @patch("cli.transfers.commands.load_token")
    @patch("cli.transfers.commands.load_mls_token")
    @patch("cli.transfers.commands.api_upload_transfer")
    def test_upload_public(self, mock_upload, mock_load_mls, mock_load_token):
        mock_load_token.return_value = self.token
        mock_load_mls.return_value = None # No MLS token needed for public? Or maybe optional.
        mock_upload.return_value = "fake_public_id"
        
        with open("test_file.txt", "w") as f:
            f.write("content")
            
        result = runner.invoke(app, ["upload", "test_file.txt", "--public"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Transferência enviada com sucesso", result.stdout)
        self.assertIn("Chave para partilha (fragmento): #", result.stdout)
        
        # Verify encrypted_keys is empty
        args, _ = mock_upload.call_args
        transfer_data = args[1]
        self.assertEqual(transfer_data["encrypted_keys"], {})
        self.assertTrue(transfer_data["is_public"])
        
        Path("test_file.txt").unlink()

    @patch("cli.transfers.commands.load_token")
    @patch("cli.transfers.commands.load_mls_token")
    @patch("cli.transfers.commands.api_get_transfer")
    @patch("cli.transfers.commands.api_download_encrypted_file")
    @patch("cli.transfers.commands.decrypt_file_with_aes_gcm")
    def test_download_public(self, mock_decrypt, mock_download_file, mock_get_transfer, mock_load_mls, mock_load_token):
        mock_load_token.return_value = self.token
        mock_load_mls.return_value = None
        
        # Mock metadata
        mock_get_transfer.return_value = {
            "cipher": "AES-256-GCM",
            "nonce": base64.b64encode(b"nonce").decode(),
            "encrypted_file_key": None # Public share might not have it for us
        }
        mock_download_file.return_value = b"encrypted_content"
        mock_decrypt.return_value = b"decrypted_content"
        
        # Fake URL with fragment
        fake_key = base64.urlsafe_b64encode(b"fake_key_32_bytes_long_exact!!!!").decode()
        transfer_url = f"http://localhost/download/123#{fake_key}"
        
        result = runner.invoke(app, ["download", transfer_url, "--output", "out.txt"])
        if result.exit_code != 0:
            print(result.stdout, file=sys.stderr)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usando chave fornecida no link público", result.stdout)
        
        # Verify decrypt called with our key
        args, _ = mock_decrypt.call_args
        self.assertEqual(args[0], b"fake_key_32_bytes_long_exact!!!!")
        
        if Path("out.txt").exists():
            Path("out.txt").unlink()

if __name__ == "__main__":
    unittest.main()
