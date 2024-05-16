
#include <cstdlib>
#include <memory>
#include <iostream>

using namespace std;


//https://github.com/CyberHashira/PKCS-11-Tutorials
// bu repodaki bazı temel fonksiyonları direkt alıp kullandım.Sign Verify
// örnekleri de vardı ama hepsi asimetrik key vs. kullanıyordu. O örnekleri
// değiştirip yazdım. 


#include <pkcs11_common.hpp>

/*
 Dokümantasyonda doğrudan random bir şekilde secret üreten bir fonksiyon görmedim
 belli başlı bir algorimtma kullanıyordu hepsi
 o yüzden random sayıyla secreti üretip createObject fonksiyonunu kullandım.
 */

void generateRandomSecret(CK_OBJECT_HANDLE &hKey) {
    CK_BYTE hmac_key[256];
    checkOperation(p11Func->C_GenerateRandom(hSession, hmac_key, sizeof (hmac_key)), "C_GenerateRandom");
    //printHex(hmac_key, sizeof(hmac_key)/sizeof(unsigned char));

    //key objesi için attribute oluştur (obje oluşturmak için attribute şart)
    CK_OBJECT_CLASS a_secret_key_class = CKO_SECRET_KEY;
    CK_BBOOL a_bool_true = CK_TRUE;
    CK_BBOOL a_bool_false = CK_FALSE;
    CK_ULONG key_size = 256;
    CK_KEY_TYPE keyttype = CKK_GENERIC_SECRET;

    CK_ATTRIBUTE attrib[] = {
        {CKA_KEY_TYPE, &keyttype, sizeof (CKK_GENERIC_SECRET)},
        {CKA_CLASS, &a_secret_key_class, sizeof (CK_OBJECT_CLASS)},
        {CKA_SIGN, &a_bool_true, sizeof (CK_BBOOL)},
        {CKA_PRIVATE, &a_bool_false, sizeof (CK_BBOOL)},
        {CKA_VALUE, hmac_key, sizeof (hmac_key)},
        {CKA_TOKEN, &a_bool_false, sizeof (CK_BBOOL)}
    };

    CK_ULONG attrib_len_hmac_key = sizeof (attrib) / sizeof (*attrib);
    checkOperation(p11Func->C_CreateObject(hSession, attrib, attrib_len_hmac_key, &hKey), "C_CreateObject");
}

void signHMAC(CK_BYTE* data, CK_OBJECT_HANDLE &hKey, std::unique_ptr<CK_BYTE>& signature, CK_ULONG sigLen) {

    CK_MECHANISM mechanism = {
        CKM_SHA256_HMAC, NULL_PTR, 0
    };

    checkOperation(p11Func->C_SignInit(hSession, &mechanism, hKey), "C_SignInit");
    //burada önce null paslayıp, sigLen doldurup yeniden çağırmayı sonucun tam boyutunu bilmediğinden 
    //yapmış değiştirmedim ben de.
    sigLen = 0;
    checkOperation(p11Func->C_Sign(hSession, data, sizeof (data), NULL, &sigLen), "C_Sign");
    signature = std::unique_ptr<CK_BYTE>{new CK_BYTE[sigLen]};
    checkOperation(p11Func->C_Sign(hSession, data, sizeof (data), signature.get(), &sigLen), "C_Sign");
    printHex(signature.get(), sigLen);
    //data[14] = 'x'; bunu yorumdan çıkarınca failliyo

}

// elemanın yazdığı fonksiyonda success dışında bir şey gelirse direk
//terminate ediyor bu yüzden checkOperation alternatifini yazdım

bool verifyHMAC(CK_BYTE* data, CK_OBJECT_HANDLE &hKey, std::unique_ptr<CK_BYTE>& signature, CK_ULONG sigLen) {
    CK_MECHANISM mechanism = {
        CKM_SHA256_HMAC, NULL_PTR, 0
    };
    checkOperation(p11Func->C_VerifyInit(hSession, &mechanism, hKey), "Verify Init");
    CK_RV rv = p11Func->C_Verify(hSession, data, sizeof (data), signature.get(), sigLen);
    if (rv != CKR_OK) {
        return true;
    } else if (rv == CKR_SIGNATURE_INVALID) {
        return false;
    } else {
        printf("RV : %#08lx", rv);
        freeResource();
        exit(1);
    }
}

// This function generates an AES-256 Key.
// Token Object | Private | Sensitive | Extractable | Modifiable | Can encrypt and decrypt 
void generateAesKey()
{
    CK_OBJECT_HANDLE objHandle = 0;
    CK_MECHANISM mech = {CKM_AES_KEY_GEN};
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR label[] = "aes_key";
    CK_ULONG keySize = 32;

    CK_ATTRIBUTE attrib[] = 
    {
        {CKA_TOKEN,         &yes,       sizeof(CK_BBOOL)},
        {CKA_PRIVATE,       &yes,       sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     &yes,       sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   &yes,       sizeof(CK_BBOOL)},
        {CKA_MODIFIABLE,    &yes,       sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,       &yes,       sizeof(CK_BBOOL)},
        {CKA_DECRYPT,       &yes,       sizeof(CK_BBOOL)},
        {CKA_LABEL,         &label,     sizeof(label)},
	{CKA_VALUE_LEN,	    &keySize,	sizeof(CK_ULONG)}
    };

    CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

    checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &objHandle), "C_GenerateKey");

    cout << "AES-256 Key generated as handle : " << objHandle << endl;
}

void generateHMACSecretKey() {
    // CKA_KEY_TYPE: key tipi (secret)
    //CKA_ID: key indentifier (Byte Array) 
    //CKA_DERIVE: key derivation destekliyor mu (false)
    //CKA_LOCAL (lokal jenere edildiyse (C_GenerateKey, C_GenerateKeyPair) ya da copy ile, CK_TRUE)
    // CK_KEY_GEN_MECHANISM (CK_MECHANISM_TYPE)
    //CKA_ALLOWED_MECHANISMS, (CK_MECHANISM_TYPE_PTR) (ARRAY)
    //CKO_SECRET_KEY, CKK_GENERIC_SECRET

    CK_OBJECT_HANDLE key_handle; //daha sonra find ile kullanılacağı için dönmeye gerek yok.


    //key objesi için attribute oluştur (obje oluşturmak için attribute şart)
    CK_OBJECT_CLASS a_secret_key_class = CKO_SECRET_KEY;
    CK_BBOOL a_true = CK_TRUE;
    CK_BBOOL a_false = CK_FALSE;
    CK_ULONG key_size = 256;
    CK_KEY_TYPE a_key_type = CKK_GENERIC_SECRET;
    CK_BYTE id[] = "721";
    //{CKA_LABEL, label, sizeof(label)-1};
    CK_MECHANISM_TYPE key_gen_mech_type = CKM_GENERIC_SECRET_KEY_GEN;
    CK_MECHANISM a_allowed_operations[] = {
        {CKM_SHA256_HMAC, NULL_PTR, 0}
    };

    //#define CKR_TEMPLATE_INCOMPLETE           0x000000D0UL
    //CKA_SENSITIVE, CKA_EXTRACTABLE vermek gerekebilir buraya
    //CKA_LOCAL eğer sen setlersen hata veriyor bu işi fonksiyona bırakman lazım gibi.

    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR label[] = "auditlog secret key1";
    CK_ULONG keySize = 256;

    CK_ATTRIBUTE attrib[] = {
        {CKA_ID, id, sizeof (id)},
        {CKA_KEY_TYPE, &a_key_type, sizeof (CK_KEY_TYPE)},
        {CKA_TOKEN, &yes, sizeof (CK_BBOOL)},
        {CKA_PRIVATE, &yes, sizeof (CK_BBOOL)},
        {CKA_SENSITIVE, &yes, sizeof (CK_BBOOL)},
        {CKA_EXTRACTABLE, &yes, sizeof (CK_BBOOL)},
        {CKA_MODIFIABLE, &yes, sizeof (CK_BBOOL)},
        {CKA_VERIFY, &yes, sizeof (CK_BBOOL)},
        {CKA_SIGN, &yes, sizeof (CK_BBOOL)},
        {CKA_LABEL, &label, sizeof (label)},
        {CKA_VALUE_LEN, &keySize, sizeof (CK_ULONG)}
    };

    //CKA_SENSITIVE = CK_TRUE, CKA_EXTRACTALBE=CK_FALSE
    //CKA_TOKEN ? tes setlersen token objesi oluyor. HSM resete kadar HSM içerisinde kalıyor obje

    //CKM_GENERIC_SECRET_KEY_GEN sadece anahtar oluşturma ile kullanılabiliyor.
    CK_MECHANISM gen_mechanism = {CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0}; //type_of_mechanism, pointer to param(if required), length of param
    std::cout << "attribute uzunluk" << sizeof (attrib) / sizeof (*attrib) << std::endl;
    std::cout << "allowed mac uzunluk" << sizeof (CKM_GENERIC_SECRET_KEY_GEN) / sizeof (CK_MECHANISM) << std::endl;

    //bu ismi refaktörle
    checkOperation(p11Func->C_GenerateKey(hSession, &gen_mechanism, attrib,
            sizeof (attrib) / sizeof (*attrib), &key_handle), "key oluştur");
    
    std::cout << "key oluşturuldu" << std::endl;

}

#include <string>
#include <locale>
#include <codecvt>
#include <regex>

std::string hexToUtf8(const std::string& hexString) {
    // Convert hexadecimal string to Unicode code point
    int codePoint = std::stoi(hexString, nullptr, 16);

    // Convert Unicode code point to UTF-8 string
    std::wstring_convert < std::codecvt_utf8<char32_t>, char32_t> converter;
    std::string utf8String = converter.to_bytes(static_cast<char32_t> (codePoint));

    return utf8String;
}

// This functions counts the number of AES keys in a token.
void countSecretKeys()
{
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE objType = CKK_AES;
    CK_OBJECT_HANDLE objHandle[10];
    CK_ULONG objCount = 0;
    CK_ULONG totalObjects = 0;

    CK_ATTRIBUTE attrib[] = 
    {
        { CKA_TOKEN, &yes, sizeof(CK_BBOOL)},
        { CKA_CLASS, &objClass, sizeof(CK_OBJECT_CLASS)},
    };
    CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

    checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectsInit");
    do
    {
        checkOperation(p11Func->C_FindObjects(hSession, objHandle, 10, &objCount), "C_FindObjects");
        totalObjects+=objCount;
    } while(objCount!=0);
    checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");
    cout << "AES keys found : " << totalObjects << endl;
}

//CryptoEngine

// generateKeySecret(); //botanda dosyaya yaz pkcs11'de makrodaki id ve label ile oluştur anahtarı
// isKeyInitialized(); //pkcsde oluşturulmuş anahtarları dön makroda tanımlanmış iddeki anahtar var mı bak, botanda dosyaya bak
// loadKey();
// Sign();
// Verify();


// PKCS11
// bunları plain text yerine encrpyt decrypt fonksiyonu implemente de yapabilirsin.
// importKey()
// exportKey()

// This functions counts the number of AES keys in a token.

void countSecretKeys1() {
    //arama kriterleri
    CK_BBOOL yes = CK_TRUE;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE objType = CKK_GENERIC_SECRET;
    //arama sonucunu tutacaklar
    CK_OBJECT_HANDLE objHandle[10]; //key objelerinin içinde tutulacağı array
    CK_ULONG objCount = 0; //kaç tane obje bulunduğunu içinde tutuacak

    //yukardakilere göre attrib doldur
    CK_ATTRIBUTE attrib[] = {
        { CKA_TOKEN, &yes, sizeof (CK_BBOOL)},
        { CKA_CLASS, &objClass, sizeof (CK_OBJECT_CLASS)},
    };
    CK_ULONG attribLen = sizeof (attrib) / sizeof (*attrib);

    //key objelerini çek.
    checkOperation(p11Func->C_FindObjectsInit(hSession, attrib, attribLen), "C_FindObjectsInit");
    //bu 100 sayısı önemli onu parametrik yapmaya çalış.
    checkOperation(p11Func->C_FindObjects(hSession, objHandle, 100, &objCount), "C_FindObjects");
    
    std::cout << "bulunan key sayısı: " << objCount << std::endl;

    //eğer obje bulunduysa (bulunmadıysa null vs dönebilirsin)
    if (objCount > 0) {
        //bulunan key objelerini işle
        for (unsigned int i = 0; i < objCount; i++){
            CK_BYTE_PTR value_handle; //labela ulaşmak için
            CK_BYTE_PTR id_handle;
            //attributelere erişmek için bu struct array gerekli. (şimdilik sadece label daha sonra id falan da ekle buraya
            CK_ATTRIBUTE template1[] = {{CKA_LABEL, NULL_PTR, 0}, {CKA_ID, NULL_PTR, 0}};
            //label boyut öğrenmek için bir defa çağırıyoruz (ulValueLen doldurmak için)
            checkOperation(p11Func->C_GetAttributeValue(hSession, objHandle[i], &template1[0], 2), "C_GetAttributeValue");
            value_handle = (CK_BYTE_PTR) malloc(template1[0].ulValueLen);
            id_handle = (CK_BYTE_PTR) malloc(template1[1].ulValueLen);
            //tempalte pointerını kendi pointerine eşitleyince kendi pointerin üzerinden erişebiiyosun.
            template1[0].pValue = value_handle;
            template1[1].pValue = id_handle;
            
            CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);
            checkOperation(p11Func->C_GetAttributeValue(hSession, objHandle[i], &template1[0], attribLen), "C_GetAttributeValue");
            std::cout << "LABEL: " << value_handle  << " id: " << id_handle << std::endl;
            free(value_handle);
            free(id_handle);

        }
    }
    
    checkOperation(p11Func->C_FindObjects(hSession, objHandle, 10, &objCount), "C_FindObjects");
    std::cout << "bulunan key sayısı: " << objCount << std::endl;

    if (objCount > 0) {
        std::cout << "daha var" << std::endl;
    }

    
    checkOperation(p11Func->C_FindObjectsFinal(hSession), "C_FindObjectsFinal");

    
    //key valid mi diye bakan bir fonksiyon yazabilirsin
}

/*
//niye hSession vermiyoruz buna argüman olarak? 96
void searchHMACKeySecret(){
    //CK_ATTRIBUTE_TYPE: attribute type, CK_VOID_PTR: pointer to value of the attribute, CK_ULONG: length in bytes of the value
    CK_ATTRIBUTE secret_key_attribute = {};
    p11Func->C_FindObjectsInit(hSession, );
}*/

int main(int argc, char **argv) {
    loadHSMLibrary();
    cout << "P11 library loaded." << endl;
    connectToSlot("1234");
    cout << "Connected via session : " << hSession << endl;

    /*
    //key handle deklare et
    CK_OBJECT_HANDLE hKey;
    //key handle doldur
    generateRandomSecret(hKey);
    //imzalanacak datayı oluştur.
    CK_BYTE data[] = "23        ,04/08/24 15:00:18,session 12 Access 234:456 operation LUNA_MODIFY_OBJECT returned LUNA_RET_SUCCESS                                                                                                                        ,89487E5EFAD41215E411E7CB03A3AA24CDDB89546AB9609F05D783C464826148";
    //imza pointer oluştur
    //CK_BYTE_PTR signature;
    std::unique_ptr<CK_BYTE> signature;
    CK_ULONG sigLen;
    //imzayı doldu.
    signHMAC(data, hKey, signature, sigLen);
    bool result = verifyHMAC(data, hKey, signature, sigLen);
        
    if (result){
        std::cout << "imza geçerli" << std::endl;
    }
    else {
        std::cout << "imza geçersiz" << std::endl;
    }*/
    //generateAesKey();
    //generateHMACSecretKey();
    //countSecretKeys();
    
    countSecretKeys1();

    disconnectFromSlot();
    cout << "Disconnected from slot." << endl;
    freeResource();
    return 0;
}