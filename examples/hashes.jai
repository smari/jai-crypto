#import "Basic";
#load "../sha.jai";

teststring :: (testname: string, a: string, b: string) {
    print("%", testname);
    if a == b { print(" ... success\n"); }
    else {
        print(" ... fail.\n");
        print("     ─ Failed comparing:\n%\n%", a, b);
    }
}

main :: () {
    testdata := "the quick brown fox jumped over the lazy dog. all work and no play makes jack a dull boy";

    teststring("SHA224", sha224sum(testdata), "4e4269f545e0b84b30a3c97486de5d6fa858337bdd59205037dc1556");
    teststring("SHA256", sha256sum(testdata), "dc8605827fae7755062045b2cabe8043265a51ff844b03c6d62a6b93f8580b96");
    teststring("SHA384", sha384sum(testdata), "1c9516bf31c60dba86a89123f969366b3d811da0af3228ff70a5b995a84a7e0479a2b93c688bde3d6f78756e20091942");
    teststring("SHA512", sha512sum(testdata), "1fd26b6e249d9df11b1acc766e6bc8db878bf3b52cc8b3ab5e5a9ba5b8dac0730b487a10410174fda37712472d9f3a56c9609f53803aad57d4d35c3ee15422ba");
}

#run main();
