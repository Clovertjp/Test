/**
 * DesSecurity.java
 */
package com.yiyou.erpaoshou.Security;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;



import com.yiyou.erpaoshou.Tool.ToolManage;
import com.yiyou.erpaoshou.beans.UserBean;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * @author pei
 * @date 创建时间：2015年6月12日 下午3:05:23 
 * @version 1.0 
 */

public class DesSecurity {
	
    /** 加密算法,可用 DES,DESede,Blowfish. */
    private final static String ALGORITHM = "DES";
    
    private final static String CLIPIV="DES/CBC/PKCS5Padding";
    
   
    private static  byte[] byt = {
		0x11,
		0x23,
		0x45,
		0x64,
		0x76,
		(byte) 0x89,
		(byte) 0xa4,
		(byte) 0xba,
		(byte) 0xcf,
		(byte) 0xef
	};
	
	 /**
     * 对数据进行DES加密.
     * @param data 待进行DES加密的数据
     * @return 返回经过DES加密后的数据
     * @throws Exception
     */
    public final static String decrypt(String data,String pwd) throws Exception {
    	BASE64Decoder decoder = new BASE64Decoder();
    	
        return new String(decrypt(decoder.decodeBuffer(data),
        		pwd));
    }
    
    
    /**
     * 对数据进行DES加密.
     * @param data 待进行DES加密的数据
     * @param user 用户数据
     * @return 返回经过DES加密后的数据
     * @throws Exception
     */
    public final static String decrypt(String data,UserBean user) throws Exception {
    	BASE64Decoder decoder = new BASE64Decoder();
    	
        return new String(decrypt(decoder.decodeBuffer(data),
        		user));
    }
    
    
    
    /**
     * 对用DES加密过的数据进行解密.
     * @param data DES加密数据
     * @return 返回解密后的数据
     * @throws Exception
     */
    public final static String encrypt(String data,String pwd) throws Exception  {
    	BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(encrypt(data.getBytes(), pwd
                ));
    }
    
    /**
     * 对用DES加密过的数据进行解密.
     * @param data DES加密数据
     * @param user 用户数据
     * @return 返回解密后的数据
     * @throws Exception
     */
    public final static String encrypt(String data,UserBean user) throws Exception  {
    	BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(encrypt(data.getBytes(), user
                ));
    }
    
    /**
     * 用指定的key对数据进行DES加密.
     * @param data 待加密的数据
     * @param key DES加密的key
     * @return 返回DES加密后的数据
     * @throws Exception
     */
    private static byte[] encrypt(byte[] data, String key) throws Exception {
        // DES算法要求有一个可信任的随机数源
       // SecureRandom sr = new SecureRandom();
    	 byte[] IV=new byte[8] ;
    	InitIV(key,IV);
    	IvParameterSpec iv = new IvParameterSpec(IV); 
    	String pwd=getFPwd(key);
        // 从原始密匙数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(pwd.getBytes("Utf-8"));
        // 创建一个密匙工厂，然后用它把DESKeySpec转换成
        // 一个SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey securekey = keyFactory.generateSecret(dks);
        // Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CLIPIV);
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, iv);
        // 现在，获取数据并加密
        // 正式执行加密操作
        
        
        return cipher.doFinal(data);
    }
    
    
    /**
     * 用指定的key对数据进行DES加密.
     * @param data 待加密的数据
     * @param user 用户数据
     * @return 返回DES加密后的数据
     * @throws Exception
     */
    private static byte[] encrypt(byte[] data, UserBean user) throws Exception {
        // DES算法要求有一个可信任的随机数源
       // SecureRandom sr = new SecureRandom();

    	IvParameterSpec iv = new IvParameterSpec(user.getIv()); 
    	String pwd=user.getDesUsePwd();

        // 从原始密匙数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(pwd.getBytes("Utf-8"));
        // 创建一个密匙工厂，然后用它把DESKeySpec转换成
        // 一个SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey securekey = keyFactory.generateSecret(dks);
        // Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(CLIPIV);
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, iv);
        // 现在，获取数据并加密
        // 正式执行加密操作
        
        
        return cipher.doFinal(data);
    }
    
    /**
     * 用指定的key对数据进行DES解密.
     * @param data 待解密的数据
     * @param key DES解密的key
     * @return 返回DES解密后的数据
     * @throws Exception
     */
    private static byte[] decrypt(byte[] data, String key) throws Exception {
        // DES算法要求有一个可信任的随机数源
       // SecureRandom sr = new SecureRandom();
    	
    	 byte[] IV=new byte[8] ;
     	InitIV(key,IV);
     	IvParameterSpec iv = new IvParameterSpec(IV); 
     	String pwd=getFPwd(key);
    	System.out.println(pwd);
        // 从原始密匙数据创建一个DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(pwd.getBytes("Utf-8"));
        // 创建一个密匙工厂，然后用它把DESKeySpec对象转换成
        // 一个SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey securekey = keyFactory.generateSecret(dks);
        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(CLIPIV);
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, iv);
        
        
        // 现在，获取数据并解密
        // 正式执行解密操作
        return cipher.doFinal(data);
    }
    
    
    /**
     * 用指定的key对数据进行DES解密.
     * @param data 待解密的数据
     * @param user 用户数据
     * @return 返回DES解密后的数据
     * @throws Exception
     */
    private static byte[] decrypt(byte[] data, UserBean user) throws Exception {
        // DES算法要求有一个可信任的随机数源
       // SecureRandom sr = new SecureRandom();
    	

     	IvParameterSpec iv = new IvParameterSpec(user.getIv()); 
     	String pwd=user.getDesUsePwd();
        // 从原始密匙数据创建一个DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(pwd.getBytes("Utf-8"));
        // 创建一个密匙工厂，然后用它把DESKeySpec对象转换成
        // 一个SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey securekey = keyFactory.generateSecret(dks);
        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(CLIPIV);
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, iv);
        
        
        // 现在，获取数据并解密
        // 正式执行解密操作
        return cipher.doFinal(data);
    }
    
    public static byte[] hex2byte(byte[] b) {
        if ((b.length % 2) != 0)
            throw new IllegalArgumentException("长度不是偶数");
        byte[] b2 = new byte[b.length / 2];
        for (int n = 0; n < b.length; n += 2) {
            String item = new String(b, n, 2);
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }
    public static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1)
                hs = hs + "0" + stmp;
            else
                hs = hs + stmp;
        }
        return hs.toUpperCase();
    }
    
    public static String toHexString(byte b[]) 
	 { 
		 StringBuffer hexString = new StringBuffer(); 
		 for (int i = 0; i < b.length; i++) 
		 { 
			 String plainText = Integer.toHexString(0xff & b[i]); 
			 if (plainText.length() < 2) 
				 plainText = "0" + plainText; 
			 hexString.append(plainText); 			
		 } 
		 return hexString.toString(); 		 
	 } 
   
    //初始化IV 与C#对应
  	public static void InitIV(String pwd,byte[] IV) throws UnsupportedEncodingException
  	{
  		byte[] t_pwd = pwd.getBytes("Utf-8");
  		
  		if (t_pwd.length <= 8) {
  			for(int i=0;i<8;i++)
  			{
  				if(i<t_pwd.length)
  				{
  					IV[i]=t_pwd[i];
  				}else
  				{
  					IV[i]=byt[8-t_pwd.length];
  				}
  			}
  			return;
  		}
  		
  		int t_num =(int) (t_pwd [t_pwd.length - 1]);
  		int sub = t_pwd.length - 8;
  		t_num = t_num % sub;
  		for (int i=0; i<8; i++) {
  			IV[i]=t_pwd[t_num+i];	
  		}
  	}
  	
  	//获取pwd 与C#对应
  	public static String getFPwd(String pwd)
  	{
  		String nowPwd = "";
  		if (pwd.length() < 8) {
			nowPwd=pwd;
			while(nowPwd.length()<8)
			{
				nowPwd+="0";
			}
		}else if(pwd.length()==8)
		{
			nowPwd=pwd;
		}else
		{
			int len=pwd.length();
			int sub=len-8;
			char[] c_pwd=pwd.toCharArray();
			char a=c_pwd[c_pwd.length-1];
			int t_num =(int) (a);
			t_num = t_num % sub;
			nowPwd=pwd.substring(t_num,t_num+8);
		}
  		return nowPwd;
  	}
    
    public static void main(String[] args) {
		try {
			String tet=encrypt("测试一下Java","94DE80BD79EA");
			System.out.println(tet);
			System.out.println(decrypt("pzTS5AzFL9re7RV/nLPLv9877z/K3mJd", "94DE80BD79EA"));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
