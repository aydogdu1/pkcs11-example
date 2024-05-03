
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
    CK_BYTE id[] = {123};
    //{CKA_LABEL, label, sizeof(label)-1};
    CK_MECHANISM_TYPE key_gen_mech_type = CKM_GENERIC_SECRET_KEY_GEN;
    CK_MECHANISM a_allowed_operations[] = {
        {CKM_SHA256_HMAC, NULL_PTR, 0}
    };

    //#define CKR_TEMPLATE_INCOMPLETE           0x000000D0UL

    //CKA_SENSITIVE, CKA_EXTRACTABLE vermek gerekebilir buraya
    //CKA_LOCAL eğer sen setlersen hata veriyor bu işi fonksiyona bırakman lazım gibi.
    CK_ATTRIBUTE key_attribute[] = {
        {CKA_KEY_TYPE, &a_key_type, sizeof (CK_KEY_TYPE)},
        {CKA_VALUE_LEN, &key_size, sizeof (CK_ULONG)},
        {CKA_ID, id, sizeof (id)},
        {CKA_DERIVE, &a_false, sizeof (CK_BBOOL)},
        {CKA_SIGN, &a_true, sizeof (CK_BBOOL)},
        {CKA_VERIFY, &a_true, sizeof (CK_BBOOL)},
        {CKA_SENSITIVE, &a_true, sizeof (CK_BBOOL)}, // Set CKA_SENSITIVE
        {CKA_EXTRACTABLE, &a_false, sizeof (CK_BBOOL)} // Set CKA_EXTRACTABLE
    };
    
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR label[] = "auditlog secret key";
    CK_ULONG keySize = 256;
    
    CK_ATTRIBUTE attrib[] = 
    {
        {CKA_ID, id, sizeof (id)},
        {CKA_KEY_TYPE, &a_key_type, sizeof (CK_KEY_TYPE)},
        {CKA_TOKEN,         &yes,       sizeof(CK_BBOOL)},
        {CKA_PRIVATE,       &yes,       sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     &yes,       sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE,   &yes,       sizeof(CK_BBOOL)},
        {CKA_MODIFIABLE,    &yes,       sizeof(CK_BBOOL)},
        {CKA_VERIFY,       &yes,       sizeof(CK_BBOOL)},
        {CKA_SIGN,       &yes,       sizeof(CK_BBOOL)},
        {CKA_LABEL,         &label,     sizeof(label)},
	{CKA_VALUE_LEN,	    &keySize,	sizeof(CK_ULONG)}
    };

    //CKA_SENSITIVE = CK_TRUE, CKA_EXTRACTALBE=CK_FALSE
    //CKA_TOKEN ? tes setlersen token objesi oluyor. HSM resete kadar HSM içerisinde kalıyor obje

    //CKM_GENERIC_SECRET_KEY_GEN sadece anahtar oluşturma ile kullanılabiliyor.
    CK_MECHANISM gen_mechanism = {CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0}; //type_of_mechanism, pointer to param(if required), length of param
    std::cout << "attribute uzunluk" << sizeof (key_attribute) / sizeof (*key_attribute) << std::endl;
    std::cout << "allowed mac uzunluk" << sizeof (CKM_GENERIC_SECRET_KEY_GEN) / sizeof (CK_MECHANISM) << std::endl;

    //bu ismi refaktörle
    checkOperation(p11Func->C_GenerateKey(hSession, &gen_mechanism, key_attribute,
            sizeof (key_attribute) / sizeof (*key_attribute), &key_handle), "key oluştur");

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

    generateHMACSecretKey();

    disconnectFromSlot();
    cout << "Disconnected from slot." << endl;
    freeResource();
    return 0;
}