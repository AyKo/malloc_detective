#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <pthread.h>

using namespace std;

struct CBaseNG {
    CBaseNG() {
        ::printf("Call CBaseNG class constructor.\n");
    }

    // !!! NOT Virtual: Not call inherit's destructor .
    ~CBaseNG() {
        ::printf("Call CBaseNG class destructor.\n");
    }
};

struct NG : public CBaseNG
{
    NG(const string& s) : CBaseNG(), data() {
        ::printf("Call NG class constructor.\n");
        data = new string(s);
        ::printf("** memory allocation: %p\n", (void*)data);        
    }
    virtual ~NG() {
        // NOT CALL
        ::printf("Call NG class destructor.\n");
        ::printf("** memory free: %p\n", (void*)data);        
        delete data;
    }
    string* data;
};

void* leak_thread(void* arg)
{
    int count = (int)(long)(arg);
    for (int i = 0; i < 100; ++i) {
        void* p = ::malloc(64+i);
        if (i == count) {
            // !!! oops..
            continue;
        }
        free(p);
    }
    return NULL;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("%s [1/2]\n", argv[0]);
        return 0;
    }
    int mode = ::atoi(argv[1]);

    if (mode == 1) {
        ::printf(
            "Case 1: Forgotton with a virtual destructor of the base class.\n"
            "--------------------------------------------------------------\n"
        );
        CBaseNG* v1 = new NG("ABC");
        void* p = reinterpret_cast<void*>(v1);
        ::printf("** memory allocation: %p\n", p);
        delete v1;
        ::printf("** memory free: %p\n", p);
    } else if (mode == 2) {
        ::printf(
            "Case 2: Not match number of calling malloc and free.\n"
            "--------------------------------------------------------------\n"
        );
        pthread_t t1, t2, t3;
        pthread_create(&t1, NULL, leak_thread, (void*)(long)10);
        pthread_create(&t2, NULL, leak_thread, (void*)(long)30);
        pthread_create(&t3, NULL, leak_thread, (void*)(long)50);
        void* res;
        pthread_join(t1, &res);
        pthread_join(t2, &res);
        pthread_join(t3, &res);
    }

    return 0;
}


// vim: ts=4 sts=4 sw=4 expandtab :

