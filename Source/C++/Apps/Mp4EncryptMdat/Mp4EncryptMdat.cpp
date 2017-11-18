/*****************************************************************
|
|    AP4 - MP4 Encrypter
|
|    Copyright 2002-2009 Axiomatic Systems, LLC
|
|
|    This file is part of Bento4/AP4 (MP4 Atom Processing Library).
|
|    Unless you have obtained Bento4 under a difference license,
|    this version of Bento4 is Bento4|GPL.
|    Bento4|GPL is free software; you can redistribute it and/or modify
|    it under the terms of the GNU General Public License as published by
|    the Free Software Foundation; either version 2, or (at your option)
|    any later version.
|
|    Bento4|GPL is distributed in the hope that it will be useful,
|    but WITHOUT ANY WARRANTY; without even the implied warranty of
|    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
|    GNU General Public License for more details.
|
|    You should have received a copy of the GNU General Public License
|    along with Bento4|GPL; see the file COPYING.  If not, write to the
|    Free Software Foundation, 59 Temple Place - Suite 330, Boston, MA
|    02111-1307, USA.
|
****************************************************************/

/*----------------------------------------------------------------------
|   includes
+---------------------------------------------------------------------*/
#include <math.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <queue>
#include <stdio.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "Ap4.h"
#include "Ap4SencAtom.h"
#include "Ap4StreamCipher.h"

/*----------------------------------------------------------------------
|   constants
+---------------------------------------------------------------------*/
#define BANNER "MP4 Encrypter - Version 1.6\n"\
               "(Bento4 Version " AP4_VERSION_STRING ")\n"\
               "(c) 2002-2016 Axiomatic Systems, LLC"

// stdout is a shared resource, so protected it with a mutex
static pthread_mutex_t console_mutex = PTHREAD_MUTEX_INITIALIZER;

/*----------------------------------------------------------------------
|   PrintUsageAndExit
+---------------------------------------------------------------------*/
static void
PrintUsageAndExit()
{
    fprintf(stderr, 
        BANNER 
        "\n\n"
        "usage: mp4encrypt --method <method> [options] <input> <output>\n"
        "     <method> is OMA-PDCF-CBC, OMA-PDCF-CTR, MARLIN-IPMP-ACBC,\n"
        "     MARLIN-IPMP-ACGK, ISMA-IAEC, PIFF-CBC, PIFF-CTR, ,MPEG-CENC,\n"
        "     MPEG-CBC1, MPEG-CENS, MPEG-CBCS\n"
        "  Options:\n"
        "  --show-progress\n"
        "      Show progress details\n"
        "  --fragments-info <filename>\n"
        "      Encrypt the fragments read from <input>, with track info read\n"
        "      from <filename>\n"
        "  --key <n>:<k>:<iv>\n"   
        "      Specifies the key to use for a track (or group key).\n"
        "      <n> is a track ID, <k> a 128-bit key in hex (32 characters)\n"
        "      and <iv> a 64-bit or 128-bit IV or salting key in hex\n"
        "      (16 or 32 characters) depending on the cipher mode\n"
        "      The key and IV values can also be specified with the keyword 'random'\n"
        "      instead of a hex-encoded value, in which case a randomly generated value\n"
        "      will be used.\n"
        "      (several --key options can be used, one for each track)\n"
        "  --strict\n"
        "      Fail if there is a warning (ex: one or more tracks would be left unencrypted)\n"
        "  --property <n>:<name>:<value>\n"
        "      Specifies a named string property for a track\n"
        "      <n> is a track ID, <name> a property name, and <value> is the\n"
        "      property value\n"
        "      (several --property options can be used, one or more for each track)\n"
        "  --global-option <name>:<value>\n"
        "      Sets the global option <name> to be equal to <value>\n"
        "  --pssh <system-id>:<filename>\n"
        "      Add a 'pssh' atom for this system ID, with the payload\n"
        "      loaded from <filename>.\n"
        "      (several --pssh options can be used, with a different system ID for each)\n"
        "      (the filename can be left empty after the ':' if no payload is needed)\n"
        "  --pssh-v1 <system-id>:<filename>\n"
        "      Same as --pssh but generates a version=1 'pssh' atom\n"
        "      (this option must appear *after* the --property options on the command line)\n"
        "  --kms-uri <uri>\n"
        "      Specifies the KMS URI for the ISMA-IAEC method\n"
        "\n"
        "  Method Specifics:\n"
        "    OMA-PDCF-CBC, MARLIN-IPMP-ACBC, MARLIN-IPMP-ACGK, PIFF-CBC, MPEG-CBC1, MPEG-CBCS: \n"
        "    the <iv> can be 64-bit or 128-bit\n"
        "    If the IV is specified as a 64-bit value, it will be padded with zeros.\n"
        "\n"
        "    OMA-PDCF-CTR, ISMA-IAEC, PIFF-CTR, MPEG-CENC, MPEG-CENS:\n"
        "    the <iv> should be a 64-bit hex string.\n"
        "    If a 128-bit value is supplied, it will be truncated to 64-bit.\n"
        "\n"
        "    OMA-PDCF-CBC, OMA-PDCF-CTR: The following properties are defined,\n"
        "    and all other properties are stored in the textual headers:\n"
        "      ContentId       -> the content ID for the track\n"
        "      RightsIssuerUrl -> the Rights Issuer URL\n"
        "\n"
        "    MARLIN-IPMP-ACBC, MARLIN-IPMP-ACGK: The following properties are defined:\n"
        "      ContentId -> the content ID for the track\n"
        "\n"
        "    MARLIN-IPMP-ACGK: The group key is specified with --key where <n>\n"
        "    is 0. The <iv> part of the key must be present, but will be ignored;\n"
        "    It should therefore be set to 0000000000000000\n"
        "\n"
        "    MPEG-CENC, MPEG-CBC1, MPEG-CENS, MPEG-CBCS, PIFF-CTR, PIFF-CBC:\n"
        "    The following properties are defined:\n"
        "      KID -> the value of KID, 16 bytes, in hexadecimal (32 characters)\n"
        "      ContentId -> Content ID mapping for KID (Marlin option)\n"
        "      PsshPadding -> pad the 'pssh' container to this size\n"
        "                    (only when using ContentId).\n"
        "                    This property should be set for track ID 0 only\n"
        );
    exit(1);
}

/*----------------------------------------------------------------------
|   constants
+---------------------------------------------------------------------*/
enum Method {
    METHOD_NONE,
    METHOD_OMA_PDCF_CBC,
    METHOD_OMA_PDCF_CTR,
    METHOD_MARLIN_IPMP_ACBC,
    METHOD_MARLIN_IPMP_ACGK,
    METHOD_PIFF_CBC,
    METHOD_PIFF_CTR,
    METHOD_MPEG_CENC,
    METHOD_MPEG_CBC1,
    METHOD_MPEG_CENS,
    METHOD_MPEG_CBCS,
    METHOD_ISMA_AES
};

class EncryptionProcessor;

class Task {
public:
    Task() {}
    virtual ~Task() {}
    virtual void run()=0;
    virtual void showTask()=0;
};

class EncodeTask : public Task {
public:
    EncodeTask(int counter, int cl);
    ~EncodeTask();
    
    virtual void run();
    
    void Feed(AP4_UI08 * buf, AP4_LargeSize buf_length);
    void Emit(const AP4_UI08 * buf, AP4_LargeSize buf_length);
    
    virtual void showTask() {
        
    }
    
    bool _closed;
private:
    AP4_MemoryByteStream * _memStream;
    EncryptionProcessor * _processor;
    int _cl;
    int _counter;
    AP4_Size _data_size;
};

/*----------------------------------------------------------------------
|   ProgressListener
+---------------------------------------------------------------------*/
class ProgressListener : public AP4_Processor::ProgressListener
{
public:
    AP4_Result OnProgress(unsigned int step, unsigned int total);
};

AP4_Result
ProgressListener::OnProgress(unsigned int step, unsigned int total)
{
    printf("\r%d/%d", step, total);
    return AP4_SUCCESS;
}

static pthread_mutex_t mutex_InputStream;
// static pthread_mutex_t mutex_DataAvail;
static sem_t *sema_full;
// static sem_t *sema_empty;

// static const AP4_UI32 OPTION_EME_PSSH           = 0x01; ///< Include a 'standard EME' pssh atom in the output
static const AP4_UI32 OPTION_PIFF_COMPATIBILITY = 0x02; ///< Attempt to create an output that is compatible with the PIFF format
static const AP4_UI32 OPTION_PIFF_IV_SIZE_16    = 0x04; ///< With the PIFF-compatibiity option, use an IV of size 16 when possible (instead of 8)
static const AP4_UI32 OPTION_IV_SIZE_8          = 0x08; ///< Use an IV of size 8 when possible (instead of 16 by default).
// static const AP4_UI32 OPTION_NO_SENC            = 0x10; ///< Don't output an 'senc' atom

class EncryptionProcessor {
private:
    // Parameters
    AP4_LargeSize m_BytesAvail;
    AP4_LargeSize m_BytesWritten;
    AP4_LargeSize m_BytesRead;
    AP4_UI32 m_Options = 0;
    AP4_CencVariant m_Variant;
    AP4_DataBuffer * m_key;
    AP4_DataBuffer * m_IV;
    // Atoms
    AP4_UI08 m_MdatHeader[8];
    AP4_MoovAtom * m_MoovAtom;
    AP4_TrakAtom * m_TrakAtom;
    AP4_StsdAtom * m_StsdAtom;
    AP4_ContainerAtom * m_MoofAtom;
    AP4_MovieFragment * m_Fragment;
    AP4_TfhdAtom* m_TfhdAtom;
    AP4_ContainerAtom * m_TrafAtom;
    AP4_FragmentSampleTable* m_SampleTable;
    AP4_MemoryByteStream * m_MdatData;
    AP4_AtomFactory * m_AtomFactory;
    // Cipher params
    AP4_BlockCipher::CipherMode  m_CipherMode;
    AP4_BlockCipher::CtrParams   m_CipherCtrParams;
    const void*                  m_CipherModeParams = NULL;
    AP4_UI08                     m_CipherIVSize = 16;
    AP4_UI08                     m_CryptByteBlock = 0;
    AP4_UI08                     m_SkipByteBlock = 0;
    bool                         m_ConstantIV = false;
    bool                         m_ResetIVAtEachSubsample = false;
    // Encoder params
    AP4_UI32 m_Format;
    unsigned int m_NALULengthSize = 0;
    AP4_UI32 m_EncFormat = 0;
    // AP4 tools
    AP4_BlockCipher* m_BlockCipher;
    AP4_CencSampleEncrypter* m_SampleEncrypter;
    AP4_StreamCipher*        m_StreamCipher = NULL;
    AP4_CencEncryptingProcessor::Encrypter * m_Encrypter;
    AP4_CencFragmentEncrypter * m_FragmentEncrypter;
    EncodeTask &m_Task;
public:
    int m_Counter;
    int m_CL;
    
    int ReadData(AP4_UI08 * buffer, int required) {
        int toRead = required;
        ssize_t rc;
        while (toRead > 0 && (rc = read(m_CL, buffer + (required - toRead), toRead)) > 0) {
            toRead -= rc;
        }
        if (rc < 0) {
            return (int)rc;
        }
        return 0;
    }
    
    AP4_MemoryByteStream * ReadAtomData() {
        AP4_UI32 size;
        AP4_UI08 sizeBuf[4];
        if (ReadData(sizeBuf, 4)) {
            return NULL;
        }
        size = (sizeBuf[0]<<24)|(sizeBuf[1]<<16)|(sizeBuf[2]<<8)|sizeBuf[3];
        pthread_mutex_lock(&console_mutex);
        // fprintf(stderr, "Atom Size: %d\n", size);
        pthread_mutex_unlock(&console_mutex);
        AP4_UI08 * data = (AP4_UI08 *)malloc(sizeof(AP4_UI08) * size);
        data[0] = (size>>24) & 0xFF;
        data[1] = (size>>16) & 0xFF;
        data[2] = (size>>8) & 0xFF;
        data[3] = (size & 0xFF);
        if (ReadData(data + 4, size - 4)) {
            return NULL;
        }
        AP4_MemoryByteStream * stream = new AP4_MemoryByteStream(data, size);
        if (data) {
            free(data);
        }
        return stream;
    }
    
    EncryptionProcessor(int counter, int cl, AP4_CencVariant variant, AP4_UI08 * key, AP4_UI08 * iv, EncodeTask &task, AP4_LargeSize totalSize) :
        m_Variant(variant), m_Task(task), m_Counter(counter), m_CL(cl) {
        switch (m_Variant) {
            case AP4_CENC_VARIANT_MPEG_CENC:
                // truncate the IV
                AP4_SetMemory(&iv[8], 0, 8);
                break;
                
            default:
                break;
        }
        
        m_key = new AP4_DataBuffer(key, 16);
        m_IV = new AP4_DataBuffer(iv, 16);
        
        m_BytesAvail = totalSize;
        m_BytesWritten = 0;
        m_BytesRead = 0;
        
        m_Encrypter = NULL;
        m_SampleTable = NULL;
        m_Fragment = NULL;
        m_FragmentEncrypter = NULL;
            
        m_AtomFactory = NULL;
        m_MdatData = NULL;
        m_MoovAtom = NULL;
    }
    
    ~EncryptionProcessor() {
        
        if (m_Encrypter) {
            delete m_Encrypter;
        }
        if (m_SampleTable) {
            delete m_SampleTable;
        }
        if (m_Fragment) {
            delete m_Fragment;
        }
        if (m_FragmentEncrypter) {
            delete m_FragmentEncrypter;
        }
        if (m_key) {
            delete m_key;
        }
        if (m_IV) {
            delete m_IV;
        }
        if (m_AtomFactory) {
            delete m_AtomFactory;
        }
        if (m_MoovAtom) {
            delete m_MoovAtom;
        }
        if (m_MdatData) {
            m_MdatData->Release();
            m_MdatData = NULL;
        }
    }
    
    void EncryptFragment() {
        m_AtomFactory = new AP4_AtomFactory();
        AP4_Atom * atom = NULL;
        
        // Moov atom
        AP4_MemoryByteStream * moovData = ReadAtomData();
        if (!moovData) {
            pthread_mutex_lock(&console_mutex);
            fprintf(stderr, "[%d] Failed to read MOOV data\n", m_Counter);
            pthread_mutex_unlock(&console_mutex);
            return;
        }
        m_AtomFactory->CreateAtomFromStream(*moovData, m_BytesAvail, atom);
        moovData->Release();
        m_MoovAtom = AP4_DYNAMIC_CAST(AP4_MoovAtom, atom);
        if (!m_MoovAtom) {
            pthread_mutex_lock(&console_mutex);
            fprintf(stderr, "[%d] Failed to get MOOV atom\n", m_Counter);
            pthread_mutex_unlock(&console_mutex);
            return;
        }
        AP4_List<AP4_TrakAtom> &trak_atoms = m_MoovAtom->GetTrakAtoms();
        if (trak_atoms.ItemCount() == 0) {
            pthread_mutex_lock(&console_mutex);
            fprintf(stderr, "[%d] Failed to get TRAK atom\n", m_Counter);
            pthread_mutex_unlock(&console_mutex);
            return;
        }
        trak_atoms.Get(0, m_TrakAtom);
        if (!m_TrakAtom) {
            pthread_mutex_lock(&console_mutex);
            fprintf(stderr, "[%d] Failed to get TRAK atom\n", m_Counter);
            pthread_mutex_unlock(&console_mutex);
            return;
        }
        m_StsdAtom = AP4_DYNAMIC_CAST(AP4_StsdAtom, m_TrakAtom->FindChild("mdia/minf/stbl/stsd"));
        
        // pthread_mutex_lock(&console_mutex);
        // fprintf(stderr, "[%d] Parsed moov atom\n", m_Counter);
        // pthread_mutex_unlock(&console_mutex);
        // Moof atom
        AP4_MemoryByteStream * moofData = ReadAtomData();
        if (!moofData) {
            // pthread_mutex_lock(&console_mutex);
            // fprintf(stderr, "[%d] Failed to read MOOF data\n", m_Counter);
            // pthread_mutex_unlock(&console_mutex);
            return;
        }
        m_AtomFactory->CreateAtomFromStream(*moofData, m_BytesAvail, atom);
        m_MoofAtom = AP4_DYNAMIC_CAST(AP4_ContainerAtom, atom);
        if (m_MoofAtom == NULL) {
            // pthread_mutex_lock(&console_mutex);
            // fprintf(stderr, "[%d] Failed to parse MOOF atom\n", m_Counter);
            // pthread_mutex_unlock(&console_mutex);
            return;
        }
        m_TrafAtom = AP4_DYNAMIC_CAST(AP4_ContainerAtom, m_MoofAtom->FindChild("traf"));
        m_TfhdAtom = AP4_DYNAMIC_CAST(AP4_TfhdAtom, m_TrafAtom->GetChild(AP4_ATOM_TYPE_TFHD));
        // pthread_mutex_lock(&console_mutex);
        // fprintf(stderr, "[%d] Parsed moof atom\n", m_Counter);
        // pthread_mutex_unlock(&console_mutex);
        
        // Create Fragment
        m_Fragment = new AP4_MovieFragment(m_MoofAtom);
        AP4_UI08 trackId = m_TfhdAtom->GetTrackId();
        
        m_MdatData = ReadAtomData();
        if (!m_MdatData) {
            // pthread_mutex_lock(&console_mutex);
            // fprintf(stderr, "[%d] Failed to read MDAT data\n", m_Counter);
            // pthread_mutex_unlock(&console_mutex);
            return;
        }
        
        m_MdatData->Read(m_MdatHeader, 8);
        m_MdatData->Seek(0);
        
        AP4_DataBuffer buffer(moofData->GetDataSize() + m_MdatData->GetDataSize());
        buffer.AppendData(moofData->GetData(), moofData->GetDataSize());
        buffer.AppendData(m_MdatData->GetData(), m_MdatData->GetDataSize());
        m_MdatData->Release();
        m_MdatData = NULL;
        m_MdatData = new AP4_MemoryByteStream(buffer.GetData(), buffer.GetDataSize());
        m_Fragment->CreateSampleTable(m_MoovAtom, trackId, m_MdatData,
                                      0,
                                      moofData->GetDataSize() + 8,
                                      0, m_SampleTable);
        moofData->Release();
        // pthread_mutex_lock(&console_mutex);
        // fprintf(stderr, "[%d] Sample count: %d\n", m_Counter, m_SampleTable->GetSampleCount());
        // pthread_mutex_unlock(&console_mutex);
        
        InitializeEncFormat();
        
        // Cipher params
        switch (m_Variant) {
            case AP4_CENC_VARIANT_PIFF_CTR:
                m_CipherMode = AP4_BlockCipher::CTR;
                m_CipherCtrParams.counter_size = 8;
                m_CipherModeParams = &m_CipherCtrParams;
                m_CipherIVSize = 8;
                break;
                
            case AP4_CENC_VARIANT_PIFF_CBC:
                m_CipherMode = AP4_BlockCipher::CBC;
                break;
                
            case AP4_CENC_VARIANT_MPEG_CENC:
                m_CipherMode = AP4_BlockCipher::CTR;
                m_CipherCtrParams.counter_size = 8;
                m_CipherModeParams = &m_CipherCtrParams;
                if ((m_Options & OPTION_IV_SIZE_8) ||
                    ((m_Options & OPTION_PIFF_COMPATIBILITY) && !(m_Options & OPTION_PIFF_IV_SIZE_16))) {
                    m_CipherIVSize = 8;
                }
                break;
                
            case AP4_CENC_VARIANT_MPEG_CENS:
                m_CipherMode = AP4_BlockCipher::CTR;
                m_CipherCtrParams.counter_size = 8;
                m_CipherModeParams = &m_CipherCtrParams;
                if (m_Options & OPTION_IV_SIZE_8) {
                    m_CipherIVSize = 8;
                }
                if (m_EncFormat == AP4_ATOM_TYPE_ENCV) {
                    m_CryptByteBlock = 1;
                    m_SkipByteBlock  = 9;
                }
                break;
                
            case AP4_CENC_VARIANT_MPEG_CBC1:
                m_CipherMode = AP4_BlockCipher::CBC;
                break;
                
            case AP4_CENC_VARIANT_MPEG_CBCS:
                m_CipherMode = AP4_BlockCipher::CBC;
                if (m_EncFormat == AP4_ATOM_TYPE_ENCV) {
                    m_CryptByteBlock = 1;
                    m_SkipByteBlock  = 9;
                }
                m_ConstantIV = true;
                m_ResetIVAtEachSubsample = true;
                break;
                
            default:
                return;
        }
        
        AP4_BlockCipherFactory &m_BlockCipherFactory = AP4_DefaultBlockCipherFactory::Instance;
        m_BlockCipherFactory.CreateCipher(AP4_BlockCipher::AES_128,
                                          AP4_BlockCipher::ENCRYPT,
                                          m_CipherMode,
                                          m_CipherModeParams,
                                          m_key->GetData(),
                                          m_IV->GetDataSize(),
                                          m_BlockCipher);
        
        InitializeSampleEncrypter();
        
        m_Encrypter = new AP4_CencEncryptingProcessor::Encrypter(m_TrakAtom->GetId(), 0, m_SampleEncrypter);
        
        m_FragmentEncrypter = new AP4_CencFragmentEncrypter(m_Variant, m_TrafAtom, m_Encrypter, 0);
        
        // pthread_mutex_lock(&console_mutex);
        // fprintf(stderr, "[%d] Processing fragment\n", m_Counter);
        // pthread_mutex_unlock(&console_mutex);
        AP4_Result result = m_FragmentEncrypter->ProcessFragment();
        if (AP4_FAILED(result)) {
            return;
        }
        // pthread_mutex_lock(&console_mutex);
        // fprintf(stderr, "Preparing for samples\n");
        // pthread_mutex_unlock(&console_mutex);
        result = m_FragmentEncrypter->PrepareForSamples(m_SampleTable);
        if (AP4_FAILED(result)) {
            // pthread_mutex_lock(&console_mutex);
            // fprintf(stderr, "[%d] Error preparing for samples\n", m_Counter);
            // pthread_mutex_unlock(&console_mutex);
            return;
        }
        // pthread_mutex_lock(&console_mutex);
        // fprintf(stderr, "[%d] Writing header\n", m_Counter);
        // pthread_mutex_unlock(&console_mutex);
        m_Encrypter->m_SampleEncrypter->SetIv(m_IV->GetData());
        AP4_Sample sample;
        m_Task.Emit(m_MdatHeader, 8);
        
        AP4_SencAtom * senc = AP4_DYNAMIC_CAST(AP4_SencAtom, m_TrafAtom->FindChild("senc"));
        AP4_CencSampleInfoTable * table = NULL;
        
        if (m_Variant == AP4_CENC_VARIANT_MPEG_CENC) {
            table = new AP4_CencSampleInfoTable(0, m_CryptByteBlock, m_SkipByteBlock, m_SampleTable->GetSampleCount(), m_CipherIVSize);
            senc->CreateSampleInfoTable(0, m_CryptByteBlock, m_SkipByteBlock, m_CipherIVSize, m_CipherIVSize, m_IV->GetData(), table);
        }
        
        if (table && table->GetSampleCount() > 0) {
            const AP4_UI08 * sample_iv = table->GetIv(0);
            if (sample_iv) {
                AP4_UI08 sampleIv[16];
                AP4_CopyMemory(sampleIv, sample_iv, 16);
                AP4_UI64 counter = (AP4_UI64)sample_iv[15]|
                ((AP4_UI64)sample_iv[14]<<8)|
                ((AP4_UI64)sample_iv[13]<<16)|
                ((AP4_UI64)sample_iv[12]<<24)|
                ((AP4_UI64)sample_iv[11]<<32)|
                ((AP4_UI64)sample_iv[10]<<40)|
                ((AP4_UI64)sample_iv[9]<<48)|
                ((AP4_UI64)sample_iv[8]<<52);
                counter = counter;
                AP4_CopyMemory(sampleIv, m_IV->GetData(), 8);
                m_Encrypter->m_SampleEncrypter->SetIv(sampleIv);
            }
        }
        
        for (AP4_Cardinal i = 0; i < m_SampleTable->GetSampleCount(); ++i) {
            result = m_SampleTable->GetSample(i, sample);
            if (AP4_FAILED(result)) {
                return;
            }
            AP4_DataBuffer data_in;
            AP4_DataBuffer data_out;
            sample.ReadData(data_in);
            result = m_FragmentEncrypter->ProcessSample(data_in, data_out);
            if (AP4_FAILED(result)) {
                return;
            }
            m_Task.Emit(data_out.GetData(), data_out.GetDataSize());
        }
        m_FragmentEncrypter->FinishFragment();
        // pthread_mutex_lock(&console_mutex);
        // fprintf(stderr, "[%d] Finished\n\n", m_Counter);
        // pthread_mutex_unlock(&console_mutex);
    }
    
    void InitializeSampleEncrypter() {
        
        switch (m_CipherMode) {
            case AP4_BlockCipher::CBC:
                m_StreamCipher = new AP4_CbcStreamCipher(m_BlockCipher);
                if (m_CryptByteBlock && m_SkipByteBlock) {
                    m_StreamCipher = new AP4_PatternStreamCipher(m_StreamCipher, m_CryptByteBlock, m_SkipByteBlock);
                }
                
                if (m_NALULengthSize) {
                    AP4_CencSubSampleMapper* subsample_mapper = NULL;
                    if (m_Variant == AP4_CENC_VARIANT_MPEG_CBCS) {
                        subsample_mapper = new AP4_CencCbcsSubSampleMapper(m_NALULengthSize, m_Format, m_TrakAtom);
                    } else {
                        subsample_mapper = new AP4_CencBasicSubSampleMapper(m_NALULengthSize, m_Format);
                    }
                    m_SampleEncrypter = new AP4_CencCbcSubSampleEncrypter(m_StreamCipher,
                                                                         m_ConstantIV,
                                                                         m_ResetIVAtEachSubsample,
                                                                         subsample_mapper);
                } else {
                    m_SampleEncrypter = new AP4_CencCbcSampleEncrypter(m_StreamCipher, m_ConstantIV);
                }
                
                break;
                
            case AP4_BlockCipher::CTR:
                m_StreamCipher = new AP4_CtrStreamCipher(m_BlockCipher, 16);
                if (m_CryptByteBlock && m_SkipByteBlock) {
                    m_StreamCipher= new AP4_PatternStreamCipher(m_StreamCipher, m_CryptByteBlock, m_SkipByteBlock);
                }
                if (m_NALULengthSize) {
                    AP4_CencSubSampleMapper* subsample_mapper = new AP4_CencAdvancedSubSampleMapper(m_NALULengthSize, m_Format);
                    m_SampleEncrypter = new AP4_CencCtrSubSampleEncrypter(m_StreamCipher,
                                                                         m_ConstantIV,
                                                                         m_ResetIVAtEachSubsample,
                                                                         m_CipherIVSize,
                                                                         subsample_mapper);
                } else {
                    m_SampleEncrypter = new AP4_CencCtrSampleEncrypter(m_StreamCipher, m_ConstantIV, m_CipherIVSize);
                }
                break;
        }
    }
    
    void InitializeEncFormat() {
        AP4_Array<AP4_SampleEntry*> entries;
        for (unsigned int i=0; i<m_StsdAtom->GetSampleDescriptionCount(); i++) {
            AP4_SampleEntry* entry = m_StsdAtom->GetSampleEntry(i);
            if (entry == NULL) {
                return;
            }
            entries.Append(entry);
        }
        if (entries.ItemCount() == 0) {
            return;
        }
        m_Format = entries[0]->GetType();
        if (m_Format == 0) {
            return;
        }
        
        if (m_Format == AP4_ATOM_TYPE_AVC1 ||
            m_Format == AP4_ATOM_TYPE_AVC2 ||
            m_Format == AP4_ATOM_TYPE_AVC3 ||
            m_Format == AP4_ATOM_TYPE_AVC4) {
            AP4_AvccAtom* avcc = AP4_DYNAMIC_CAST(AP4_AvccAtom, entries[0]->GetChild(AP4_ATOM_TYPE_AVCC));
            if (avcc) {
                m_NALULengthSize = avcc->GetNaluLengthSize();
            }
        } else if (m_Format == AP4_ATOM_TYPE_HEV1 ||
                   m_Format == AP4_ATOM_TYPE_HVC1) {
            AP4_HvccAtom* hvcc = AP4_DYNAMIC_CAST(AP4_HvccAtom, entries[0]->GetChild(AP4_ATOM_TYPE_HVCC));
            if (hvcc) {
                m_NALULengthSize = hvcc->GetNaluLengthSize();
            }
        }
        
        switch (m_Format) {
            case AP4_ATOM_TYPE_MP4A:
                m_EncFormat = AP4_ATOM_TYPE_ENCA;
                break;
                
            case AP4_ATOM_TYPE_MP4V:
            case AP4_ATOM_TYPE_AVC1:
            case AP4_ATOM_TYPE_AVC2:
            case AP4_ATOM_TYPE_AVC3:
            case AP4_ATOM_TYPE_AVC4:
            case AP4_ATOM_TYPE_HEV1:
            case AP4_ATOM_TYPE_HVC1:
                m_EncFormat = AP4_ATOM_TYPE_ENCV;
                break;
                
            default: {
                // try to find if this is audio or video
                AP4_HdlrAtom* hdlr = AP4_DYNAMIC_CAST(AP4_HdlrAtom, m_TrakAtom->FindChild("mdia/hdlr"));
                if (hdlr) {
                    switch (hdlr->GetHandlerType()) {
                        case AP4_HANDLER_TYPE_SOUN:
                            m_EncFormat = AP4_ATOM_TYPE_ENCA;
                            break;
                            
                        case AP4_HANDLER_TYPE_VIDE:
                            m_EncFormat = AP4_ATOM_TYPE_ENCV;
                            break;
                    }
                }
                break;
            }
        }
    }
};

const char * socket_path = "/tmp/viero-aes-socket";

class Thread {
public:
    Thread() {
        state = EState_None;
        handle = 0;
    }
    
    virtual ~Thread() {
        assert(state != EState_Started || joined);
    }
    
    void start() {
        assert(state == EState_None);
        // in case of thread create error I usually FatalExit...
        if (pthread_create(&handle, NULL, threadProc, this))
            abort();
        state = EState_Started;
    }
    
    void join() {
        // A started thread must be joined exactly once!
        // This requirement could be eliminated with an alternative implementation but it isn't needed.
        assert(state == EState_Started);
        pthread_join(handle, NULL);
        state = EState_Joined;
    }
    
protected:
    virtual void run() = 0;
    
private:
    static void* threadProc(void* param) {
        Thread* thread = reinterpret_cast<Thread*>(param);
        thread->run();
        return NULL;
    }
    
private:
    enum EState {
        EState_None,
        EState_Started,
        EState_Joined
    };
    
    EState state;
    bool joined;
    pthread_t handle;
};

class WorkQueue {
public:
    WorkQueue() {
        pthread_mutex_init(&qmtx,0);
        
        // wcond is a condition variable that's signaled
        // when new work arrives
        pthread_cond_init(&wcond, 0);
    }
    
    ~WorkQueue() {
        // Cleanup pthreads
        pthread_mutex_destroy(&qmtx);
        pthread_cond_destroy(&wcond);
    }
    
    // Retrieves the next task from the queue
    Task *nextTask() {
        // The return value
        Task *nt = 0;
        
        // Lock the queue mutex
        pthread_mutex_lock(&qmtx);
        
        while (tasks.empty())
            pthread_cond_wait(&wcond, &qmtx);
        
        nt = tasks.front();
        tasks.pop();
        
        // Unlock the mutex and return
        pthread_mutex_unlock(&qmtx);
        return nt;
    }
    // Add a task
    void addTask(Task *nt) {
        // Lock the queue
        pthread_mutex_lock(&qmtx);
        // Add the task
        tasks.push(nt);
        // signal there's new work
        pthread_cond_signal(&wcond);
        // Unlock the mutex
        pthread_mutex_unlock(&qmtx);
    }
    
private:
    std::queue<Task*> tasks;
    pthread_mutex_t qmtx;
    pthread_cond_t wcond;
};

class PoolWorkerThread : public Thread {
public:
    PoolWorkerThread(WorkQueue& _work_queue) : work_queue(_work_queue) {}
protected:
    virtual void run()
    {
        while (Task* task = work_queue.nextTask())
            task->run();
    }
private:
    WorkQueue& work_queue;
};

class ThreadPool {
public:
    // Allocate a thread pool and set them to work trying to get tasks
    ThreadPool(int n) {
        printf("Creating a thread pool with %d threads\n", n);
        for (int i=0; i<n; ++i)
        {
            threads.push_back(new PoolWorkerThread(workQueue));
            threads.back()->start();
        }
    }
    
    // Wait for the threads to finish, then delete them
    ~ThreadPool() {
        finish();
    }
    
    // Add a task
    void addTask(Task *nt) {
        workQueue.addTask(nt);
    }
    
    // Asking the threads to finish, waiting for the task
    // queue to be consumed and then returning.
    void finish() {
        for (size_t i=0,e=threads.size(); i<e; ++i)
            workQueue.addTask(NULL);
        for (size_t i=0,e=threads.size(); i<e; ++i)
        {
            threads[i]->join();
            delete threads[i];
        }
        threads.clear();
    }
    
private:
    std::vector<PoolWorkerThread*> threads;
    WorkQueue workQueue;
};

EncodeTask::EncodeTask(int counter, int cl) : Task(), _cl(cl), _counter(counter) {
}

EncodeTask::~EncodeTask() {
    _closed = true;
    close(_cl);
    _cl = NULL;
    // pthread_mutex_lock(&console_mutex);
    // printf("[%d] Socket closed\n", _processor->m_Counter);
    // pthread_mutex_unlock(&console_mutex);
    delete _processor;
}

void EncodeTask::run() {
    const int capacity = 65535;
    unsigned char buf[capacity + 1];
    
    ssize_t rc;
    
    int toRead = 4;
    while (toRead > 0 && (rc = read(_cl, buf + 4 - toRead, toRead)) > 0) {
        toRead -= rc;
    }
    if (rc == -1 || rc == 0) {
        // pthread_mutex_lock(&console_mutex);
        // printf("[%d] Something's wrong with reading size\n", _counter);
        // pthread_mutex_unlock(&console_mutex);
        return;
    }
    AP4_Size data_len = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|(buf[3]);
    if (data_len == 0xFFFFFF) {
        return;
    }
    char variant[5]; variant[4] = 0;
    toRead = 4;
    while (toRead > 0 && (rc = read(_cl, variant + 4 - toRead, toRead)) > 0) {
        toRead -= rc;
    }
    if (rc == -1 || rc == 0) {
        // pthread_mutex_lock(&console_mutex);
        // printf("[%d] Something's wrong with reading type\n", _counter);
        // pthread_mutex_unlock(&console_mutex);
        return;
    }
    AP4_CencVariant theVariant = (AP4_CompareStrings(variant, "cenc") == 0) ? AP4_CENC_VARIANT_MPEG_CENC : AP4_CENC_VARIANT_MPEG_CBCS;
    AP4_UI08 key_bin[16];
    AP4_UI08 iv_bin[16];
    toRead = 16;
    while (toRead > 0 && (rc = read(_cl, key_bin + 16 - toRead, toRead)) > 0) {
        toRead -= rc;
    }
    if (rc == -1 || rc == 0) {
        // pthread_mutex_lock(&console_mutex);
        // printf("[%d] Something's wrong with reading key\n", _counter);
        // pthread_mutex_unlock(&console_mutex);
        return;
    }
    toRead = 16;
    while (toRead > 0 && (rc = read(_cl, iv_bin + 16 - toRead, toRead)) > 0) {
        toRead -= rc;
    }
    if (rc == -1 || rc == 0) {
        // pthread_mutex_lock(&console_mutex);
        // printf("[%d] Something's wrong with reading iv\n", _counter);
        // pthread_mutex_unlock(&console_mutex);
        return;
    }
    
    _processor = new EncryptionProcessor(_counter, _cl, theVariant, key_bin, iv_bin, *this, data_len);
    
    _processor->EncryptFragment();
    
    delete this;
};

void EncodeTask::Emit(const AP4_UI08 * buf, AP4_LargeSize buf_length) {
    write(this->_cl, buf, buf_length);
};

void handler(int s) {
    printf("Caught SIGPIPE\n");
}

/*----------------------------------------------------------------------
|   main
+---------------------------------------------------------------------*/
int
main(int argc, char** argv)
{
    ThreadPool *tp = new ThreadPool(4);
    sockaddr_un addr;
    int fd,cl;

    if (argc > 1) socket_path=argv[1];

    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*socket_path == '\0') {
        *addr.sun_path = '\0';
        strncpy(addr.sun_path+1, socket_path+1, sizeof(addr.sun_path)-2);
    } else {
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
        unlink(socket_path);
    }

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind error");
        exit(-1);
    }

    if (listen(fd, 5) == -1) {
        perror("listen error");
        exit(-1);
    }
    pthread_mutex_init(&mutex_InputStream, NULL);
    sema_full = sem_open("/io_sema", O_CREAT, 0644, 0);
    int counter = 1;
    int set = 1;
    setsockopt(fd, SOL_SOCKET, 0x1022, (void *)&set, sizeof(int));
    try {
        while (1) {
            if ( (cl = accept(fd, NULL, NULL)) < 0) {
                perror("accept error");
                continue;
            }

            EncodeTask * task = new EncodeTask(counter, cl);
            tp->addTask(task);
            counter++;
        }
    } catch (std::exception e) {
        pthread_mutex_destroy(&mutex_InputStream);
        delete tp;
    }
    return 0;
}
