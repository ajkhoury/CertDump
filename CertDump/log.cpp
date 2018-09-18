#include "log.h"

#include <openssl/bio.h>

BIO *
BIO_open_default( 
    char mode 
)
{
    BIO *ret = NULL;

    if (mode == 'r')
    {
        ret = BIO_new_fp( stdin, BIO_NOCLOSE | BIO_FP_TEXT );
    }
    else if (mode == 'w')
    {
        ret = BIO_new_fp( stdout, BIO_NOCLOSE | BIO_FP_TEXT );
    }

    return ret;
}

void
BIO_dump_buffer(
    struct bio_st* bp,
    uint8_t *Buffer,
    size_t BufferLength,
    uint8_t Indent,
    bool Offset,
    bool Wait
)
{
    size_t i, j;
    uintptr_t addr;
    size_t indentLen;
    char indentString[32];

    indentLen = (size_t)Indent;
    if (indentLen > 0)
    {
        memset( indentString, ' ', indentLen );
        indentString[indentLen] = '\0';
    }

    BIO_printf( bp, "%sBuffer 0x%08zX (%u bytes):", ((indentLen > 0) ? indentString : ""), (uintptr_t)Buffer, BufferLength );

    for (i = 0; i < BufferLength / 16; i++)
    {
        addr = (i * 16);
        if (!Offset)
            addr += (uintptr_t)Buffer;

        BIO_printf( bp, "\n%s0x%08zX  ", ((indentLen > 0) ? indentString : ""), addr );

        for (j = 0; j < 16; j++)
        {
            BIO_printf( bp, "%02X ", Buffer[(i * 16) + j] );
        }

        BIO_write( bp, " ", 1 );

        for (j = 0; j < 16; j++)
        {
            int c = (int)Buffer[(i * 16) + j];
            BIO_write( bp, isprint( c ) ? (char*)&c : ".", 1 );
        }
    }

    if (BufferLength % 16 != 0)
    {
        addr = (i * 16);
        if (!Offset)
            addr += (uintptr_t)Buffer;

        BIO_printf( bp, "\n%s0x%08zX  ", ((indentLen > 0) ? indentString : ""), addr );

        for (j = 0; j < 16; j++)
        {
            if (j < BufferLength % 16)
                BIO_printf( bp, "%02X ", Buffer[(i * 16) + j] );
            else
                BIO_printf( bp, "   " );
        }

        BIO_write( bp, " ", 1 );

        for (j = 0; j < BufferLength % 16; j++)
        {
            int c = (int)Buffer[(i * 16) + j];
            BIO_write( bp, isprint( c ) ? (char*)&c : ".", 1 );
        }
    }

    if (Wait)
    {
        BIO_puts( bp, "\npress any key to continue..." );
        getchar( );
    }
    else
    {
        BIO_write( bp, "\n", 1 );
    }
}