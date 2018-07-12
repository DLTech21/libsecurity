/*================================================================
*   Copyright (C) 2015 All rights reserved.
*   
*   文件名称：security.h
*
#pragma once
================================================================*/

#ifndef __SECURITY_H__
#define __SECURITY_H__


#ifdef _WIN32
typedef char			int8_t;
typedef short			int16_t;
typedef int				int32_t;
typedef	long long		int64_t;
typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int	uint32_t;
typedef	unsigned long long	uint64_t;
typedef int				socklen_t;
#else
#include <stdint.h>
#endif
typedef unsigned char	uchar_t;

#ifdef WIN32
#define DLL_MODIFIER __declspec(dllexport)
#else
#define DLL_MODIFIER
#endif


#ifdef __cplusplus
extern "C" {
#endif
    
#ifdef __ANDROID__
    jbyteArray Java_io_github_dltech21_Security_EncryptByKey(JNIEnv* env, jobject obj, jstring jstr, jstring jstrKey);
    jbyteArray Java_io_github_dltech21_Security_DecryptByKey(JNIEnv* env, jobject obj, jstring jstr, jstring jstrKey);
    jbyteArray Java_io_github_dltech21_Security_EncryptContent(JNIEnv* env, jobject obj, jstring jstr);
    jbyteArray Java_io_github_dltech21_Security_DecryptContent(JNIEnv* env, jobject obj, jstring jstr);
    jbyteArray Java_io_github_dltech21_Security_EncryptPass(JNIEnv* env, jobject obj, jstring jstr);

#else
    /**
     *  带key对内容加密
     *
     *  @param pInData  待加密的消息内容指针
     *  @param nInLen   待加密消息内容长度
     *  @param keyData  加密key指针 只能传入32位
     *  @param keyInLen 加密key长度 长度只能是32
     *  @param pOutData 加密后的文本
     *  @param nOutLen  加密后的文本长度
     *
     *  @return 返回 0-成功; 其他-失败
     */
    DLL_MODIFIER int EncryptByKey(const char* pInData, uint32_t nInLen, const char *keyData, uint32_t keyInLen, char** pOutData, uint32_t& nOutLen);
    
    /**
     *  带key对内容解密
     *
     *  @param pInData  待解密的消息内容指针
     *  @param nInLen   待解密消息内容长度
     *  @param keyData  加密key指针 只能传入32位
     *  @param keyInLen 加密key长度 长度只能是32
     *  @param pOutData 解密后的文本
     *  @param nOutLen  解密后的文本长度
     *
     *  @return 返回 0-成功; 其他-失败
     */
    DLL_MODIFIER int DecryptByKey(const char* pInData, uint32_t nInLen, const char *keyData, uint32_t keyInLen, char** pOutData, uint32_t& nOutLen);
    

    DLL_MODIFIER int EncryptContent(const char* pInData, uint32_t nInLen, char** pOutData, uint32_t& nOutLen);
    DLL_MODIFIER int DecryptContent(const char* pInData, uint32_t nInLen, char** pOutData, uint32_t& nOutLen);

    /**
     *  对密码进行加密
     *
     *  @param pInData  待加密的消息内容指针
     *  @param nInLen   待加密消息内容长度
     *  @param pOutData 加密后的文本
     *  @param nOutLen  加密后的文本长度
     *
     *  @return 返回 0-成功; 其他-失败
     */
    DLL_MODIFIER int EncryptPass(const char* pInData, uint32_t nInLen, char** pOutData, uint32_t& nOutLen);
    /**
     *  释放资源
     *
     *  @param pOutData 需要释放的资源
     */
    DLL_MODIFIER void Free(char* pOutData);
    
#endif
    
#ifdef __cplusplus
}
#endif

#endif
