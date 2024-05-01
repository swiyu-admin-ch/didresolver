## How to install

### ios

Add the bindings/swift/didresolver.xcframework as a library in xCode
Copy the bindings/swift/files/did.swift to your project

### Android

Add "net.java.dev.jna:jna:5.13.0@aar" as a dependency
Create the folder "bindings/kotlin/jniLibs" under app/src/main
Copy bindings/kotlin/uniffi/did/did.kt to your project (in the package uniffi.did)

## How to use

### Swift

```swift
let did = Did(text: "did:web:gist.githubusercontent.com:bit-jniestroj:7fb3cce550db5a239b543035298429fe:raw:5e5540c6f67ffe30cca2dfc4bb950a68f412c406")
do {
    let diddoc = try did.resolve()
    
    print(diddoc)
} catch {
    print("Error \(error)")
}
```
