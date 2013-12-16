package com.jestinstoffel.sqrldroid.test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import junit.framework.TestCase;

import org.mockito.Matchers;
import org.mockito.Mockito;

import com.jestinstoffel.sqrldroid.SqrlClient;
import com.jestinstoffel.sqrldroid.SqrlData;
import com.jestinstoffel.sqrldroid.SqrlIdentity;
import com.jestinstoffel.sqrldroid.crypto.HmacGenerator;
import com.jestinstoffel.sqrldroid.crypto.PbkdfHandler;
import com.jestinstoffel.sqrldroid.crypto.RandomByteGenerator;
import com.jestinstoffel.sqrldroid.crypto.SqrlSigner;

public class SqrlClientTests extends TestCase {
	
	// The class to test
	private SqrlClient mClient;
	
	// Dependencies
	private HmacGenerator mHmac;
	private PbkdfHandler mPbkdf;
	private SqrlSigner mSigner;
	private RandomByteGenerator mPrng;

	protected void setUp() throws Exception {
		super.setUp();
		
		// mock dependencies
		mHmac = Mockito.mock(HmacGenerator.class);
		mPbkdf = Mockito.mock(PbkdfHandler.class);
		mSigner = Mockito.mock(SqrlSigner.class);
		mPrng = Mockito.mock(RandomByteGenerator.class);
		
		// instantiate the class to be tested
		mClient = new SqrlClient(mHmac, mPbkdf, mSigner, mPrng);
	}

	protected void tearDown() throws Exception {
		super.tearDown();
		
		mHmac = null;
		mPbkdf = null;
		mSigner = null;
		mPrng = null;
		mClient = null;
	}

	public void testCalculateMasterKey_Succeeds() {
		Mockito.when(mPbkdf.generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		byte[] result = null;
		try {
			result = mClient.calculateMasterKey(new byte[32], "password", new byte[8]);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mPbkdf).generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class));
		assertNotNull(result);
		assertEquals(32, result.length);
	}
	
	public void testCalculateMasterKey_Bad_MasterIdentityKey_Fails() {
		Mockito.when(mPbkdf.generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		try {
			byte[] result = mClient.calculateMasterKey(new byte[31], "password", new byte[8]);
		} catch (Exception e) {
			assertEquals("master identity key must be 256 bits (32 bytes).", e.getMessage());
			return;
		}
		
		fail("Should never make it this far");
	}
	
	public void testCalculateMasterKey_Bad_PBKDF_Output_Fails() {
		Mockito.when(mPbkdf.generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[31]);
		
		try {
			byte[] result = mClient.calculateMasterKey(new byte[32], "password", new byte[8]);
		} catch (Exception e) {
			assertEquals("password key must be 256 bits (32 bytes).  Check validity of PBKDF.", e.getMessage());
			return;
		}
		
		fail("Should never make it this far");
	}

	public void testCalculateMasterIdentityKey_Succeeds() {
		Mockito.when(mPbkdf.generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		byte[] result = null;
		try {
			result = mClient.calculateMasterIdentityKey(new byte[32], "password", new byte[8]);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mPbkdf).generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class));
		assertNotNull(result);
		assertEquals(32, result.length);
	}
	
	public void testCalculateMasterIdentityKey_Bad_PBKDF_Output_Fails() {
		Mockito.when(mPbkdf.generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[31]);
		
		try {
			byte[] result = mClient.calculateMasterIdentityKey(new byte[32], "password", new byte[8]);
		} catch (Exception e) {
			assertEquals("password key must be 256 bits (32 bytes).  Check validity of PBKDF.", e.getMessage());
			return;
		}
		
		fail("Should never make it this far");
	}

	public void testGetSqrlDataForLoginByteArrayString_Succeeds() throws InvalidKeyException, NoSuchAlgorithmException {
		String url = "sqrl://example.com/auth/asdkjhaiewruhaksdfjiugasdfkjb";
		Mockito.when(mHmac.generatePrivateKey(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[32]);
		Mockito.when(mSigner.sign(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[64]);
		Mockito.when(mSigner.makePublicKey(Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		SqrlData result = null;
		try {
			result = mClient.getSqrlDataForLogin(new byte[32], url);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mHmac).generatePrivateKey(Matchers.any(byte[].class), Matchers.anyString());
		Mockito.verify(mSigner).sign(Matchers.any(byte[].class), Matchers.anyString());
		Mockito.verify(mSigner).makePublicKey(Matchers.any(byte[].class));
		
		assertNotNull(result);
		assertEquals(url.replace("sqrl://", ""), result.url);
	}

	public void testCreateIdentity_Succeeds() {
		Mockito.when(mPbkdf.generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[32]);
		Mockito.when(mPbkdf.getPartialHashFromPasswordKey(Matchers.any(byte[].class))).thenReturn(new byte[16]);
		
		SqrlIdentity result = null;
		try {
			result = mClient.createIdentity("password", new byte[4096]);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mPbkdf).generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class));
		Mockito.verify(mPbkdf).getPartialHashFromPasswordKey(Matchers.any(byte[].class));
		assertNotNull(result);
	}

	public void testChangePassword_Succeeds() {
		Mockito.when(mPbkdf.generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[32]);
		Mockito.when(mPbkdf.getPartialHashFromPasswordKey(Matchers.any(byte[].class))).thenReturn(new byte[16]);
		
		SqrlIdentity result = null;
		try {
			result = mClient.changePassword("oldpassword", new byte[8], "newpassword", new byte[32]);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mPbkdf, Mockito.times(2)).generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class));
		Mockito.verify(mPbkdf).getPartialHashFromPasswordKey(Matchers.any(byte[].class));
		assertNotNull(result);
	}

	public void testVerifyPassword_Succeeds() {
		Mockito.when(mPbkdf.verifyPassword(Matchers.anyString(), Matchers.any(byte[].class), Matchers.any(byte[].class))).thenReturn(true);
		
		boolean result = mClient.verifyPassword("password", new SqrlIdentity());
		
		Mockito.verify(mPbkdf).verifyPassword(Matchers.anyString(), Matchers.any(byte[].class), Matchers.any(byte[].class));
		assertTrue(result);
	}
	
	public void testVerifyPassword_Fails() {
		Mockito.when(mPbkdf.verifyPassword(Matchers.anyString(), Matchers.any(byte[].class), Matchers.any(byte[].class))).thenReturn(false);
		
		boolean result = mClient.verifyPassword("password", new SqrlIdentity());
		
		Mockito.verify(mPbkdf).verifyPassword(Matchers.anyString(), Matchers.any(byte[].class), Matchers.any(byte[].class));
		assertFalse(result);
	}

	public void testGetDomainFromUrl_SQRL_Succeeds() throws InvalidKeyException, NoSuchAlgorithmException {
		String url = "sqrl://example.com/auth/asdkjhaiewruhaksdfjiugasdfkjb";
		Mockito.when(mHmac.generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com"))).thenReturn(new byte[32]);
		Mockito.when(mSigner.sign(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[64]);
		Mockito.when(mSigner.makePublicKey(Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		SqrlData result = null;
		try {
			result = mClient.getSqrlDataForLogin(new byte[32], url);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mHmac).generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com"));
		Mockito.verify(mSigner).sign(Matchers.any(byte[].class), Matchers.anyString());
		Mockito.verify(mSigner).makePublicKey(Matchers.any(byte[].class));
		assertNotNull(result);
		assertEquals(url.replace("sqrl://", ""), result.url);
	}
	
	public void testGetDomainFromUrl_QRL_Succeeds() throws InvalidKeyException, NoSuchAlgorithmException {
		String url = "qrl://example.com/auth/asdkjhaiewruhaksdfjiugasdfkjb";
		Mockito.when(mHmac.generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com"))).thenReturn(new byte[32]);
		Mockito.when(mSigner.sign(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[64]);
		Mockito.when(mSigner.makePublicKey(Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		SqrlData result = null;
		try {
			result = mClient.getSqrlDataForLogin(new byte[32], url);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mHmac).generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com"));
		Mockito.verify(mSigner).sign(Matchers.any(byte[].class), Matchers.anyString());
		Mockito.verify(mSigner).makePublicKey(Matchers.any(byte[].class));
		assertNotNull(result);
		assertEquals(url.replace("qrl://", ""), result.url);
	}
	
	public void testGetDomainFromUrl_SQRL_Pipe_Succeeds() throws InvalidKeyException, NoSuchAlgorithmException {
		String url = "sqrl://example.com/auth|/asdkjhaiewruhaksdfjiugasdfkjb";
		Mockito.when(mHmac.generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com/auth"))).thenReturn(new byte[32]);
		Mockito.when(mSigner.sign(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[64]);
		Mockito.when(mSigner.makePublicKey(Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		SqrlData result = null;
		try {
			result = mClient.getSqrlDataForLogin(new byte[32], url);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mHmac).generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com/auth"));
		Mockito.verify(mSigner).sign(Matchers.any(byte[].class), Matchers.anyString());
		Mockito.verify(mSigner).makePublicKey(Matchers.any(byte[].class));
		assertNotNull(result);
		assertEquals(url.replace("sqrl://", ""), result.url);
	}
	
	public void testGetDomainFromUrl_QRL_Pipe_Succeeds() throws InvalidKeyException, NoSuchAlgorithmException {
		String url = "qrl://example.com/auth|/asdkjhaiewruhaksdfjiugasdfkjb";
		Mockito.when(mHmac.generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com/auth"))).thenReturn(new byte[32]);
		Mockito.when(mSigner.sign(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[64]);
		Mockito.when(mSigner.makePublicKey(Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		SqrlData result = null;
		try {
			result = mClient.getSqrlDataForLogin(new byte[32], url);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mHmac).generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com/auth"));
		Mockito.verify(mSigner).sign(Matchers.any(byte[].class), Matchers.anyString());
		Mockito.verify(mSigner).makePublicKey(Matchers.any(byte[].class));
		assertNotNull(result);
		assertEquals(url.replace("qrl://", ""), result.url);
	}
	
	public void testGetDomainFromUrl_Bad_Scheme_Fails() throws InvalidKeyException, NoSuchAlgorithmException {
		String url = "http://example.com/auth/asdkjhaiewruhaksdfjiugasdfkjb";
		Mockito.when(mHmac.generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com"))).thenReturn(new byte[32]);
		Mockito.when(mSigner.sign(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[64]);
		Mockito.when(mSigner.makePublicKey(Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		SqrlData result = null;
		try {
			result = mClient.getSqrlDataForLogin(new byte[32], url);
		} catch (Exception e) {
			assertEquals("SQRL urls must begin with 'sqrl://' or 'qrl://'", e.getLocalizedMessage());
			return;
		}
		
		fail("Should never make it this far");
	}
	
	public void testGetDomainFromUrl_Bad_Url_Fails() throws InvalidKeyException, NoSuchAlgorithmException {
		String url = "sqrl://example.com";
		Mockito.when(mHmac.generatePrivateKey(Matchers.any(byte[].class), Matchers.eq("example.com"))).thenReturn(new byte[32]);
		Mockito.when(mSigner.sign(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[64]);
		Mockito.when(mSigner.makePublicKey(Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		SqrlData result = null;
		try {
			result = mClient.getSqrlDataForLogin(new byte[32], url);
		} catch (Exception e) {
			assertEquals("SQRL urls must contain a '/'", e.getLocalizedMessage());
			return;
		}
		
		fail("Should never make it this far");
	}

	public void testXor() {
		byte[] passwordKey = new byte[]
		{
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // seriously Java?  No unsigned types?  Not even for bytes?  Ridiculous!
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		};

		byte[] masterIdentityKey = new byte[]
		{
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		};

		byte[] masterKey = new byte[]
		{
			0x00, 0x00, 0x00, 0x00,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		};

		Mockito.when(mPbkdf.generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(passwordKey);

		byte[] result = null;
		try {
			result = mClient.calculateMasterKey(masterIdentityKey, "password", new byte[8]);
		} catch (Exception e) {
			fail(e.getMessage());
		}

		Mockito.verify(mPbkdf).generatePasswordKey(Matchers.anyString(), Matchers.any(byte[].class));
		assertEquals(result.length, 32);
		assertTrue(Arrays.equals(result, masterKey));
	}
}
