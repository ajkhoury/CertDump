#ifndef _LOG_H_
#define _LOG_H_

#ifdef _WIN32
#pragma once
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#if defined(_DEBUG)
#define LogInfo(Format, ...) \
    printf( "[INFO][%s] " Format "\n", __FUNCTION__, ##__VA_ARGS__ )
#define LogWarning(Format, ...) \
	printf("[WARN][%s] " Format "\n", __FUNCTION__, ##__VA_ARGS__)
#define LogError(Format, ...) \
	printf("[ERROR][%s] " Format "\n", __FUNCTION__, ##__VA_ARGS__)
#else
#define LogInfo(Format, ...)       ((void)Format)
#define LogWarning(Format, ...)    ((void)Format)
#define LogError(Format, ...)      ((void)Format)
#endif

struct bio_st *
BIO_open_default( 
        char mode 
        );

void
BIO_dump_buffer(
    struct bio_st* bp,
    uint8_t *Buffer,
    size_t BufferLength,
    uint8_t Indent,
    bool Offset,
    bool Wait
    );

static
void
LogDumpBuffer(
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

    //printf( "%sBuffer 0x%IX (%Iu bytes):", ((indentLen > 0) ? indentString : ""), (uintptr_t)Buffer, BufferLength );
    printf( "Buffer 0x%IX (%Iu bytes):", (uintptr_t)Buffer, BufferLength );

    for (i = 0; i < BufferLength / 16; i++)
    {
        addr = (i * 16);
        if (!Offset)
            addr += (uintptr_t)Buffer;

        printf( "\n%s0x%08IX  ", ((indentLen > 0) ? indentString : ""), addr );
        
        for (j = 0; j < 16; j++)
        {
            printf( "%02X ", Buffer[(i * 16) + j] );
        }

        putchar( ' ' );

        for (j = 0; j < 16; j++)
        {
            int c = (int)Buffer[(i * 16) + j];
            putchar( isprint( c ) ? c : '.' );
        }
    }

    if (BufferLength % 16 != 0)
    {
        addr = (i * 16);
        if (!Offset)
            addr += (uintptr_t)Buffer;

        printf( "\n%s0x%08IX  ", ((indentLen > 0) ? indentString : ""), addr );

        for (j = 0; j < 16; j++)
        {
            if (j < BufferLength % 16)
                printf( "%02X ", Buffer[(i * 16) + j] );
            else
                printf( "   " );
        }

        putchar( ' ' );

        for (j = 0; j < BufferLength % 16; j++)
        {
            int c = (int)Buffer[(i * 16) + j];
            putchar( isprint( c ) ? c : '.' );
        }
    }

    if (Wait)
    {
        puts( "\npress any key to continue..." );
        getchar( );
    }
    else
    {
        putchar( '\n' );
    }
}

static
void
LogDumpCompareBuffers(
    uint8_t *Buffer1,
    uint8_t *Buffer2,
    uint32_t BufferLength
)
{
    uint32_t i, j, k;

    printf( "         Buffer1 0x%IX         Buffer2 0x%IX", (uintptr_t)Buffer1, (uintptr_t)Buffer2 );

    i = j = 0;
    for (;;)
    {
        getchar( );
        printf( "\n%04X  ", i );

        do
        {
            printf( "%02X ", Buffer1[i] );
            i++;
            if (i == BufferLength)
                break;
        } while (i == 0 || (i % 8) != 0);

        if ((i % 8) != 0)
        {
            for (k = 0; k < 8 - (i % 8); k++)
                printf( "   " );
        }
        printf( "   " );

        do
        {
            printf( "%02X ", Buffer2[j] );
            j++;
            if (j == BufferLength)
                goto done;
        } while (j == 0 || (j % 8) != 0);
    }

done:
    printf( "\npress any key to continue...\n" );
    getchar( );
}


#endif // _LOG_H_