# Example App

```
gcc -c -o zuo.o -DZUO_EMBEDDED zuo.c
gcc -c -o example-app.o $(curl-config --cflags) $(xml2-config --cflags) example-app.c
gcc -o example-app example-app.o zuo.o $(curl-config --static-libs) /build/lib/libxml2.a -lm
```

