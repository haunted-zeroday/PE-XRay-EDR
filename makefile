CC = g++

SRCS = main.c core/pe_analyzer.c core/src/pe_x86.c core/src/pe_x64.c src/scanner.c

TARGET = PE-XRay.exe

# Определяем пути
IDIR = -Iinclude -Icore/include
LDIR = -Llib

LIBS = -liup -liupcd -liupimglib -liupim \
       -lcd -lim -lz \
       -lgdi32 -lcomctl32 -lole32 -loleaut32 -luuid -lwintrust -lwindowscodecs -lshlwapi

CFLAGS = $(IDIR) -m64 -mwindows -O2 -s -DNDEBUG -ffunction-sections -fdata-sections -Wl,--gc-sections -static

$(TARGET): $(SRCS)
	windres --target=pe-x86-64 icons.rc icons.o
	$(CC) $(SRCS) -o $(TARGET) $(CFLAGS) $(LDIR) $(LIBS) icons.o

clean:
	del $(TARGET)