/*================================================================
 *   Copyright (C) 2015 All rights reserved.
 *
 *   文件名称：security.cpp
 *
 #include "security.h"
 ================================================================*/
#ifdef __ANDROID__
#include <jni.h>
#include <android/log.h>
#include <elf.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#define LOGV(...) ((void)__android_log_print(ANDROID_LOG_VERBOSE, "native-activity", __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "native-activity", __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, "native-activity", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "native-activity", __VA_ARGS__))
#define JNIREG_CLASS "io/github/dltech21/Security"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "aes.h"
#include "aes_locl.h"
#include "base64.h"
#include "../../include/security.h"
#include "md5.h"

uint32_t ReadUint32(uchar_t *buf)
{
    uint32_t data = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    return data;
}

void WriteUint32(uchar_t *buf, uint32_t data)
{
    buf[0] = static_cast<uchar_t>(data >> 24);
    buf[1] = static_cast<uchar_t>((data >> 16) & 0xFF);
    buf[2] = static_cast<uchar_t>((data >> 8) & 0xFF);
    buf[3] = static_cast<uchar_t>(data & 0xFF);
}


#ifdef __cplusplus
extern "C" {
#endif
    
#ifdef __ANDROID__
    
    static JNINativeMethod gMethods[] = {
        { "EncryptByKey", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)EncryptByKey},
        { "DecryptByKey", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", (void*)DecryptByKey},
        { "EncryptContent", "(Ljava/lang/String;)Ljava/lang/String;", (void*)EncryptContent},
        { "DecryptContent", "(Ljava/lang/String;)Ljava/lang/String;", (void*)DecryptContent},
        { "EncryptPass", "(Ljava/lang/String;)Ljava/lang/String;", (void*)EncryptPass},
    };
    
    static int registerNativeMethods(JNIEnv* env, const char* className,
                                     JNINativeMethod* gMethods, int numMethods)
    {
        jclass clazz;
        clazz = env->FindClass( className);
        if (clazz == NULL) {
            return JNI_FALSE;
        }
        if (env->RegisterNatives( clazz, gMethods, numMethods) < 0) {
            return JNI_FALSE;
        }
        
        return JNI_TRUE;
    }
    
    static int registerNatives(JNIEnv* env)
    {
        if (!registerNativeMethods(env, JNIREG_CLASS, gMethods,
                                   sizeof(gMethods) / sizeof(gMethods[0])))
            return JNI_FALSE;
        
        return JNI_TRUE;
    }
    
    //签名信息
    const char *app_sha1="FD305F186972DEA0F22F09C72C03975F6ACB02DB";
    const char hexcode[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

    jobject getApplication(JNIEnv *env) {
        jobject application = NULL;
        jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
        if (activity_thread_clz != NULL) {
            jmethodID currentApplication = env->GetStaticMethodID(
                                                                  activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
            if (currentApplication != NULL) {
                application = env->CallStaticObjectMethod(activity_thread_clz, currentApplication);
            } else {
                LOGE("Cannot find method: currentApplication() in ActivityThread.");
            }
            env->DeleteLocalRef(activity_thread_clz);
        } else {
            LOGE("Cannot find class: android.app.ActivityThread");
        }
        
        return application;
    }
    
    char* getSha1(JNIEnv *env){
        //上下文对象
        jobject application = getApplication(env);
        if (application == NULL) {
            return NULL;
        }
        jclass context_class = env->GetObjectClass(application);
        
        //反射获取PackageManager
        jmethodID methodId = env->GetMethodID(context_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
        jobject package_manager = env->CallObjectMethod(application, methodId);
        if (package_manager == NULL) {
            LOGE("package_manager is NULL!!!");
            return NULL;
        }
        
        //反射获取包名
        methodId = env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
        jstring package_name = (jstring)env->CallObjectMethod(application, methodId);
        if (package_name == NULL) {
            LOGE("package_name is NULL!!!");
            return NULL;
        }
        env->DeleteLocalRef(context_class);
        
        //获取PackageInfo对象
        jclass pack_manager_class = env->GetObjectClass(package_manager);
        methodId = env->GetMethodID(pack_manager_class, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
        env->DeleteLocalRef(pack_manager_class);
        jobject package_info = env->CallObjectMethod(package_manager, methodId, package_name, 0x40);
        if (package_info == NULL) {
            LOGE("getPackageInfo() is NULL!!!");
            return NULL;
        }
        env->DeleteLocalRef(package_manager);
        
        //获取签名信息
        jclass package_info_class = env->GetObjectClass(package_info);
        jfieldID fieldId = env->GetFieldID(package_info_class, "signatures", "[Landroid/content/pm/Signature;");
        env->DeleteLocalRef(package_info_class);
        jobjectArray signature_object_array = (jobjectArray)env->GetObjectField(package_info, fieldId);
        if (signature_object_array == NULL) {
            LOGE("signature is NULL!!!");
            return NULL;
        }
        jobject signature_object = env->GetObjectArrayElement(signature_object_array, 0);
        env->DeleteLocalRef(package_info);
        
        //签名信息转换成sha1值
        jclass signature_class = env->GetObjectClass(signature_object);
        methodId = env->GetMethodID(signature_class, "toByteArray", "()[B");
        env->DeleteLocalRef(signature_class);
        jbyteArray signature_byte = (jbyteArray) env->CallObjectMethod(signature_object, methodId);
        jclass byte_array_input_class=env->FindClass("java/io/ByteArrayInputStream");
        methodId=env->GetMethodID(byte_array_input_class,"<init>","([B)V");
        jobject byte_array_input=env->NewObject(byte_array_input_class,methodId,signature_byte);
        jclass certificate_factory_class=env->FindClass("java/security/cert/CertificateFactory");
        methodId=env->GetStaticMethodID(certificate_factory_class,"getInstance","(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
        jstring x_509_jstring=env->NewStringUTF("X.509");
        jobject cert_factory=env->CallStaticObjectMethod(certificate_factory_class,methodId,x_509_jstring);
        methodId=env->GetMethodID(certificate_factory_class,"generateCertificate",("(Ljava/io/InputStream;)Ljava/security/cert/Certificate;"));
        jobject x509_cert=env->CallObjectMethod(cert_factory,methodId,byte_array_input);
        env->DeleteLocalRef(certificate_factory_class);
        jclass x509_cert_class=env->GetObjectClass(x509_cert);
        methodId=env->GetMethodID(x509_cert_class,"getEncoded","()[B");
        jbyteArray cert_byte=(jbyteArray)env->CallObjectMethod(x509_cert,methodId);
        env->DeleteLocalRef(x509_cert_class);
        jclass message_digest_class=env->FindClass("java/security/MessageDigest");
        methodId=env->GetStaticMethodID(message_digest_class,"getInstance","(Ljava/lang/String;)Ljava/security/MessageDigest;");
        jstring sha1_jstring=env->NewStringUTF("SHA1");
        jobject sha1_digest=env->CallStaticObjectMethod(message_digest_class,methodId,sha1_jstring);
        methodId=env->GetMethodID(message_digest_class,"digest","([B)[B");
        jbyteArray sha1_byte=(jbyteArray)env->CallObjectMethod(sha1_digest,methodId,cert_byte);
        env->DeleteLocalRef(message_digest_class);
        
        //转换成char
        jsize array_size=env->GetArrayLength(sha1_byte);
        jbyte* sha1 =env->GetByteArrayElements(sha1_byte,NULL);
        char *hex_sha=new char[array_size*2+1];
        for (int i = 0; i <array_size ; ++i) {
            hex_sha[2*i]=hexcode[((unsigned char)sha1[i])/16];
            hex_sha[2*i+1]=hexcode[((unsigned char)sha1[i])%16];
        }
        hex_sha[array_size*2]='\0';
        
        LOGV("hex_sha %s ",hex_sha);
        return hex_sha;
    }
    
    jboolean checkValidity(JNIEnv *env,char *sha1){
        //比较签名
        if (strcmp(sha1,app_sha1)==0)
        {
            LOGV("验证成功");
            return true;
        }
        LOGV("验证失败");
        return false;
    }
    
    jint JNI_OnLoad(JavaVM *vm, void *reserved) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);//反调试
        
        JNIEnv *env = NULL;
        if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
            return JNI_ERR;
        }
        
        if (!registerNatives(env)) {//注册
            return JNI_ERR;
        }
        
        char *sha1 = getSha1(env);
        jboolean result = checkValidity(env,sha1);
        if(result){
            return JNI_VERSION_1_4;
        }else{
            return JNI_ERR;
        }
    }

    __attribute__((section (".mytext"))) JNICALL jstring EncryptByKey(JNIEnv* env, jobject obj, jstring jstr, jstring jstrKey)
    {
        const char *pInData = env->GetStringUTFChars(jstr, NULL);		//待加密内容,转换格式
        uint32_t nInLen = strlen(pInData);
        
        uint32_t nRemain = nInLen % 16;
        uint32_t nBlocks = (nInLen + 15) / 16;
        
        if (nRemain > 12 || nRemain == 0) {
            nBlocks += 1;
        }
        uint32_t nEncryptLen = nBlocks * 16;
        
        unsigned char* pData = (unsigned char*) calloc(nEncryptLen, 1);
        memcpy(pData, pInData, nInLen);
        env->ReleaseStringUTFChars(jstr,pInData);
        
        unsigned char* pEncData = (unsigned char*) malloc(nEncryptLen);
        
        WriteUint32((pData + nEncryptLen - 4), nInLen);
        AES_KEY aesKey;
        const char *key = env->GetStringUTFChars(jstrKey, NULL);
        AES_set_encrypt_key((const unsigned char*)key, 256, &aesKey);
        for (uint32_t i = 0; i < nBlocks; i++) {
            AES_encrypt(pData + i * 16, pEncData + i * 16, &aesKey);
        }
        
        free(pData);
        string strEnc((char*)pEncData, nEncryptLen);
        free(pEncData);
        env->ReleaseStringUTFChars(jstrKey,key);
        string strDec = base64_encode(strEnc);
        
        jbyteArray carr = env->NewByteArray(strDec.length());
        env->SetByteArrayRegion(carr,0,strDec.length(),(jbyte*)strDec.c_str());
        
        jclass strClass = env->FindClass("java/lang/String");
        jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
        jstring encoding = env->NewStringUTF("utf-8");
        jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
        return str;
    }
    
    /**
     * 解密
     */
    __attribute__((section (".mytext"))) JNICALL jstring DecryptByKey(JNIEnv* env, jobject obj, jstring jstr, jstring jstrKey)
    {
        jclass strClass = env->FindClass("java/lang/String");
        jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
        jstring encoding = env->NewStringUTF("utf-8");
        
        const char *pInData = env->GetStringUTFChars(jstr, NULL);   //获取待揭秘内容,转换格式
        uint32_t nInLen = strlen(pInData);
        string strInData(pInData, nInLen);
        env->ReleaseStringUTFChars(jstr,pInData);
        std::string strResult = base64_decode(strInData);
        uint32_t nLen = (uint32_t)strResult.length();
        if(nLen == 0)
        {
            jbyteArray carr = env->NewByteArray(0);
            jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
            return str;
        }
        
        const unsigned char* pData = (const unsigned char*) strResult.c_str();
        
        if (nLen % 16 != 0) {
            jbyteArray carr = env->NewByteArray(0);
            jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
            return str;
        }
        // 先申请nLen 个长度，解密完成后的长度应该小于该长度
        char* pTmp = (char*)malloc(nLen + 1);
        
        uint32_t nBlocks = nLen / 16;
        AES_KEY aesKey;
        
        const char *key = env->GetStringUTFChars(jstrKey, NULL);
        AES_set_decrypt_key((const unsigned char*) key, 256, &aesKey);           //设置AES解密密钥
        for (uint32_t i = 0; i < nBlocks; i++) {
            AES_decrypt(pData + i * 16, (unsigned char*)pTmp + i * 16, &aesKey);
        }
        uchar_t* pStart = (uchar_t*)pTmp+nLen-4;
        uint32_t nOutLen = ReadUint32(pStart);
        
        if(nOutLen > nLen)
        {
            free(pTmp);
            jbyteArray carr = env->NewByteArray(0);
            jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
            return str;
        }
        pTmp[nOutLen] = 0;
        jbyteArray carr = env->NewByteArray(nOutLen);
        env->SetByteArrayRegion(carr,0,nOutLen,(jbyte*)pTmp);
        env->ReleaseStringUTFChars(jstrKey,key);
        free(pTmp);
        
        jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
        return str;
    }

    __attribute__((section (".mytext"))) JNICALL jstring EncryptContent(JNIEnv* env, jobject obj, jstring jstr)
    {
        const char *pInData = env->GetStringUTFChars(jstr, NULL);       //待加密内容,转换格式
        uint32_t nInLen = strlen(pInData);
        
        uint32_t nRemain = nInLen % 16;
        uint32_t nBlocks = (nInLen + 15) / 16;
        
        if (nRemain > 12 || nRemain == 0) {
            nBlocks += 1;
        }
        uint32_t nEncryptLen = nBlocks * 16;
        
        unsigned char* pData = (unsigned char*) calloc(nEncryptLen, 1);
        memcpy(pData, pInData, nInLen);
        env->ReleaseStringUTFChars(jstr,pInData);
        
        unsigned char* pEncData = (unsigned char*) malloc(nEncryptLen);
        
        WriteUint32((pData + nEncryptLen - 4), nInLen);
        AES_KEY aesKey;
        const char *key = "42ac40b2e40f06fb1836228fc7c1e587";
        AES_set_encrypt_key((const unsigned char*)key, 256, &aesKey);
        for (uint32_t i = 0; i < nBlocks; i++) {
            AES_encrypt(pData + i * 16, pEncData + i * 16, &aesKey);
        }
        
        free(pData);
        string strEnc((char*)pEncData, nEncryptLen);
        free(pEncData);
        string strDec = base64_encode(strEnc);
        
        jbyteArray carr = env->NewByteArray(strDec.length());
        env->SetByteArrayRegion(carr,0,strDec.length(),(jbyte*)strDec.c_str());
        
        jclass strClass = env->FindClass("java/lang/String");
        jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
        jstring encoding = env->NewStringUTF("utf-8");
        jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
        return str;
    }
    
    /**
     * 解密
     */
    __attribute__((section (".mytext"))) JNICALL jstring DecryptContent(JNIEnv* env, jobject obj, jstring jstr)
    {
        jclass strClass = env->FindClass("java/lang/String");
        jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
        jstring encoding = env->NewStringUTF("utf-8");
        
        const char *pInData = env->GetStringUTFChars(jstr, NULL);   //获取待揭秘内容,转换格式
        uint32_t nInLen = strlen(pInData);
        string strInData(pInData, nInLen);
        env->ReleaseStringUTFChars(jstr,pInData);
        std::string strResult = base64_decode(strInData);
        uint32_t nLen = (uint32_t)strResult.length();
        if(nLen == 0)
        {
            jbyteArray carr = env->NewByteArray(0);
            jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
            return str;
        }
        
        const unsigned char* pData = (const unsigned char*) strResult.c_str();
        
        if (nLen % 16 != 0) {
            jbyteArray carr = env->NewByteArray(0);
            jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
            return str;
        }
        // 先申请nLen 个长度，解密完成后的长度应该小于该长度
        char* pTmp = (char*)malloc(nLen + 1);
        
        uint32_t nBlocks = nLen / 16;
        AES_KEY aesKey;
        
        const char *key = "42ac40b2e40f06fb1836228fc7c1e587";
        AES_set_decrypt_key((const unsigned char*) key, 256, &aesKey);           //设置AES解密密钥
        for (uint32_t i = 0; i < nBlocks; i++) {
            AES_decrypt(pData + i * 16, (unsigned char*)pTmp + i * 16, &aesKey);
        }
        uchar_t* pStart = (uchar_t*)pTmp+nLen-4;
        uint32_t nOutLen = ReadUint32(pStart);
        
        if(nOutLen > nLen)
        {
            free(pTmp);
            jbyteArray carr = env->NewByteArray(0);
            jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
            return str;
        }
        pTmp[nOutLen] = 0;
        jbyteArray carr = env->NewByteArray(nOutLen);
        env->SetByteArrayRegion(carr,0,nOutLen,(jbyte*)pTmp);
        free(pTmp);
        
        jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
        return str;
    }
    
    __attribute__((section (".mytext"))) JNICALL jstring EncryptPass(JNIEnv* env, jobject obj, jstring jstr)
    {
        jclass strClass = env->FindClass("java/lang/String");
        jmethodID ctorID = env->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
        jstring encoding = env->NewStringUTF("utf-8");
        
        const char *pInData = env->GetStringUTFChars(jstr, NULL);		//待加密内容,转换格式
        uint32_t nInLen = strlen(pInData);
        if(pInData == NULL || nInLen <=0)
        {
            env->ReleaseStringUTFChars(jstr,pInData);
            jbyteArray carr = env->NewByteArray(0);
            jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
            return str;
        }
        char *pTmp = (char*)malloc(33);
        if(pTmp == NULL)
        {
            env->ReleaseStringUTFChars(jstr,pInData);
            jbyteArray carr = env->NewByteArray(0);
            jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
            return str;
        }
        MD5_Calculate(pInData, nInLen, pTmp);
        pTmp[32] = 0;
        env->ReleaseStringUTFChars(jstr,pInData);
        
        jbyteArray carr = env->NewByteArray(32);
        env->SetByteArrayRegion(carr,0,32,(jbyte*)pTmp);
        free(pTmp);
        jstring str = (jstring)env->NewObject(strClass, ctorID, carr, encoding);
        return str;
    }
    
#else
    int EncryptByKey(const char* pInData, uint32_t nInLen, const char *keyData, uint32_t keyInLen, char** ppOutData, uint32_t& nOutLen)
    {
        if(keyData == NULL|| keyInLen !=32 )
        {
            return -1;
        }
        if(pInData == NULL|| nInLen <=0 )
        {
            return -1;
        }
        uint32_t nRemain = nInLen % 16;
        uint32_t nBlocks = (nInLen + 15) / 16;
        
        if (nRemain > 12 || nRemain == 0) {
            nBlocks += 1;
        }
        uint32_t nEncryptLen = nBlocks * 16;
        
        unsigned char* pData = (unsigned char*) calloc(nEncryptLen, 1);
        memcpy(pData, pInData, nInLen);
        unsigned char* pEncData = (unsigned char*) malloc(nEncryptLen);

        WriteUint32((pData + nEncryptLen - 4), nInLen);
        AES_KEY aesKey;
        
        const char *key = keyData;
        AES_set_encrypt_key((const unsigned char*)key, 256, &aesKey);
        for (uint32_t i = 0; i < nBlocks; i++) {
            AES_encrypt(pData + i * 16, pEncData + i * 16, &aesKey);
        }

        free(pData);
        string strEnc((char*)pEncData, nEncryptLen);
        free(pEncData);
        string strDec = base64_encode(strEnc);
        nOutLen = (uint32_t)strDec.length();
        
        char* pTmp = (char*) malloc(nOutLen + 1);
        memcpy(pTmp, strDec.c_str(), nOutLen);
        pTmp[nOutLen] = 0;
        *ppOutData = pTmp;
        return 0;
    }
    
    int DecryptByKey(const char* pInData, uint32_t nInLen, const char *keyData, uint32_t keyInLen, char** ppOutData, uint32_t& nOutLen)
    {
        if(keyData == NULL|| keyInLen !=32 )
        {
            return -1;
        }
        if(pInData == NULL|| nInLen <=0 )
        {
            return -1;
        }
        string strInData(pInData, nInLen);
        std::string strResult = base64_decode(strInData);
        uint32_t nLen = (uint32_t)strResult.length();
        if(nLen == 0)
        {
            return -2;
        }

        const unsigned char* pData = (const unsigned char*) strResult.c_str();

        if (nLen % 16 != 0) {
            return -3;
        }
        // 先申请nLen 个长度，解密完成后的长度应该小于该长度
        char* pTmp = (char*)malloc(nLen + 1);

        uint32_t nBlocks = nLen / 16;
        AES_KEY aesKey;
        
        const char *key = keyData;
        AES_set_decrypt_key((const unsigned char*) key, 256, &aesKey);           //设置AES解密密钥
        for (uint32_t i = 0; i < nBlocks; i++) {
            AES_decrypt(pData + i * 16, (unsigned char*)pTmp + i * 16, &aesKey);
        }

        uchar_t* pStart = (uchar_t*)pTmp+nLen-4;
        nOutLen = ReadUint32(pStart);
//        printf("%u\n", nOutLen);
        if(nOutLen > nLen)
        {
            free(pTmp);
            return -4;
        }
        pTmp[nOutLen] = 0;
        *ppOutData = pTmp;
        return 0;
    }

    int EncryptContent(const char* pInData, uint32_t nInLen, char** ppOutData, uint32_t& nOutLen)
    {
        if(pInData == NULL|| nInLen <=0 )
        {
            return -1;
        }
        uint32_t nRemain = nInLen % 16;
        uint32_t nBlocks = (nInLen + 15) / 16;
        
        if (nRemain > 12 || nRemain == 0) {
            nBlocks += 1;
        }
        uint32_t nEncryptLen = nBlocks * 16;
        
        unsigned char* pData = (unsigned char*) calloc(nEncryptLen, 1);
        memcpy(pData, pInData, nInLen);
        unsigned char* pEncData = (unsigned char*) malloc(nEncryptLen);

        WriteUint32((pData + nEncryptLen - 4), nInLen);
        AES_KEY aesKey;
        
        const char *key = "00111946655405188575651534545107";
        AES_set_encrypt_key((const unsigned char*)key, 256, &aesKey);
        for (uint32_t i = 0; i < nBlocks; i++) {
            AES_encrypt(pData + i * 16, pEncData + i * 16, &aesKey);
        }

        free(pData);
        string strEnc((char*)pEncData, nEncryptLen);
        free(pEncData);
        string strDec = base64_encode(strEnc);
        nOutLen = (uint32_t)strDec.length();
        
        char* pTmp = (char*) malloc(nOutLen + 1);
        memcpy(pTmp, strDec.c_str(), nOutLen);
        pTmp[nOutLen] = 0;
        *ppOutData = pTmp;
        return 0;
    }
    
    int DecryptContent(const char* pInData, uint32_t nInLen, char** ppOutData, uint32_t& nOutLen)
    {
        if(pInData == NULL|| nInLen <=0 )
        {
            return -1;
        }
        string strInData(pInData, nInLen);
        std::string strResult = base64_decode(strInData);
        uint32_t nLen = (uint32_t)strResult.length();
        if(nLen == 0)
        {
            return -2;
        }

        const unsigned char* pData = (const unsigned char*) strResult.c_str();

        if (nLen % 16 != 0) {
            return -3;
        }
        // 先申请nLen 个长度，解密完成后的长度应该小于该长度
        char* pTmp = (char*)malloc(nLen + 1);

        uint32_t nBlocks = nLen / 16;
        AES_KEY aesKey;
        
        const char *key = "00111946655405188575651534545107";
        AES_set_decrypt_key((const unsigned char*) key, 256, &aesKey);           //设置AES解密密钥
        for (uint32_t i = 0; i < nBlocks; i++) {
            AES_decrypt(pData + i * 16, (unsigned char*)pTmp + i * 16, &aesKey);
        }

        uchar_t* pStart = (uchar_t*)pTmp+nLen-4;
        nOutLen = ReadUint32(pStart);
//        printf("%u\n", nOutLen);
        if(nOutLen > nLen)
        {
            free(pTmp);
            return -4;
        }
        pTmp[nOutLen] = 0;
        *ppOutData = pTmp;
        return 0;
    }

    int EncryptPass(const char* pInData, uint32_t nInLen, char** ppOutData, uint32_t& nOutLen)
    {
        if(pInData == NULL|| nInLen <=0 )
        {
            return -1;
        }
        char *pTmp = (char*)malloc(33);
        MD5_Calculate(pInData, nInLen, pTmp);
        pTmp[32] = 0;
        *ppOutData = pTmp;
        nOutLen = 32;
        return 0;
    }
    
    void Free(char* pOutData)
    {
        if(pOutData)
        {
            free(pOutData);
            pOutData = NULL;
        }
    }
    
    
#endif
    
#ifdef __cplusplus
}
#endif
