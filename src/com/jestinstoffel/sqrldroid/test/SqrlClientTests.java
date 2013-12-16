package com.jestinstoffel.sqrldroid.test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import junit.framework.TestCase;

import org.mockito.Matchers;
import org.mockito.Mockito;

import com.jestinstoffel.sqrldroid.SqrlClient;
import com.jestinstoffel.sqrldroid.SqrlData;
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

	public void testSqrlClient() {
		fail("Not yet implemented");
	}

	public void testCalculateMasterKey_Succeeds() {
		Mockito.when(mPbkdf.GeneratePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		byte[] result = null;
		try {
			result = mClient.CalculateMasterKey(new byte[32], "password", new byte[8]);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mPbkdf).GeneratePasswordKey(Matchers.anyString(), Matchers.any(byte[].class));
		assertNotNull(result);
		assertEquals(32, result.length);
	}
	
	public void testCalculateMasterKey_Bad_MasterIdentityKey_Fails() {
		Mockito.when(mPbkdf.GeneratePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		try {
			byte[] result = mClient.CalculateMasterKey(new byte[31], "password", new byte[8]);
		} catch (Exception e) {
			assertEquals("master identity key must be 256 bits (32 bytes).", e.getMessage());
			return;
		}
		
		fail("Should never make it this far");
	}
	
	public void testCalculateMasterKey_Bad_PBKDF_Output_Fails() {
		Mockito.when(mPbkdf.GeneratePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[31]);
		
		try {
			byte[] result = mClient.CalculateMasterKey(new byte[32], "password", new byte[8]);
		} catch (Exception e) {
			assertEquals("password key must be 256 bits (32 bytes).  Check validity of PBKDF.", e.getMessage());
			return;
		}
		
		fail("Should never make it this far");
	}

	public void testCalculateMasterIdentityKey_Succeeds() {
		Mockito.when(mPbkdf.GeneratePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		byte[] result = null;
		try {
			result = mClient.CalculateMasterIdentityKey(new byte[32], "password", new byte[8]);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mPbkdf).GeneratePasswordKey(Matchers.anyString(), Matchers.any(byte[].class));
		assertNotNull(result);
		assertEquals(32, result.length);
	}
	
	public void testCalculateMasterIdentityKey_Bad_PBKDF_Output_Fails() {
		Mockito.when(mPbkdf.GeneratePasswordKey(Matchers.anyString(), Matchers.any(byte[].class))).thenReturn(new byte[31]);
		
		try {
			byte[] result = mClient.CalculateMasterIdentityKey(new byte[32], "password", new byte[8]);
		} catch (Exception e) {
			assertEquals("password key must be 256 bits (32 bytes).  Check validity of PBKDF.", e.getMessage());
			return;
		}
		
		fail("Should never make it this far");
	}

	public void testGetSqrlDataForLoginByteArrayString_Succeeds() throws InvalidKeyException, NoSuchAlgorithmException {
		String url = "sqrl://example.com/auth/asdkjhaiewruhaksdfjiugasdfkjb";
		Mockito.when(mHmac.GeneratePrivateKey(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[32]);
		Mockito.when(mSigner.Sign(Matchers.any(byte[].class), Matchers.anyString())).thenReturn(new byte[64]);
		Mockito.when(mSigner.MakePublicKey(Matchers.any(byte[].class))).thenReturn(new byte[32]);
		
		SqrlData result = null;
		try {
			result = mClient.GetSqrlDataForLogin(new byte[32], url);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		
		Mockito.verify(mHmac).GeneratePrivateKey(Matchers.any(byte[].class), Matchers.anyString());
		Mockito.verify(mSigner).Sign(Matchers.any(byte[].class), Matchers.anyString());
		Mockito.verify(mSigner).MakePublicKey(Matchers.any(byte[].class));
		
		assertNotNull(result);
		assertEquals(url.replace("sqrl://", ""), result.Url);
	}

	public void testGetSqrlDataForLoginByteArrayStringByteArrayString() {
		fail("Not yet implemented");
	}

	public void testGetSqrlDataForLoginSqrlIdentityStringString() {
		fail("Not yet implemented");
	}

	public void testCreateIdentity() {
		fail("Not yet implemented");
	}

	public void testChangePassword() {
		fail("Not yet implemented");
	}

	public void testVerifyPassword() {
		fail("Not yet implemented");
	}

	public void testGetDomainFromUrl() {
		fail("Not yet implemented");
	}

}
