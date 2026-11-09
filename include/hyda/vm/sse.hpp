#pragma once

#include <cstdint>

namespace hyda {

enum class SseBin : uint8_t {
  AddSS = 0, AddSD, AddPS, AddPD,
  SubSS, SubSD, SubPS, SubPD,
  MulSS, MulSD, MulPS, MulPD,
  DivSS, DivSD, DivPS, DivPD,
  MinSS, MinSD, MinPS, MinPD,
  MaxSS, MaxSD, MaxPS, MaxPD,
  AndPS, AndPD, AndNPS, AndNPD, OrPS, OrPD, XorPS, XorPD,
  PAnd, PAndN, POr, PXor,
  PAddB, PAddW, PAddD, PAddQ, PSubB, PSubW, PSubD, PSubQ,

  PAddSB, PAddSW, PAddUSB, PAddUSW,
  PSubSB, PSubSW, PSubUSB, PSubUSW,

  PMullW, PMulHW, PMulHUW, PMulLD, PMulUDQ, PMaddWD,

  PMinUB, PMinSW, PMinUD, PMaxUB, PMaxSW, PMaxUD,

  PCmpeqB, PCmpeqW, PCmpeqD, PCmpgtB, PCmpgtW, PCmpgtD,

  PunpckLBW, PunpckLWD, PunpckLDQ, PunpckHBW, PunpckHWD, PunpckHDQ,

  PackssWB, PackssDW, PackusWB,

  PabsB, PabsW, PabsD, PavgB, PavgW, PsignB, PsignW, PsignD,
};

enum class SseUn : uint8_t {
  SqrtSS = 0, SqrtSD, SqrtPS, SqrtPD,
};

enum class SseCmp : uint8_t {
  ComiSS = 0, UcomiSS, ComiSD, UcomiSD,
};

enum class SseCvt : uint8_t {
  Si2SS32 = 0, Si2SS64, Si2SD32, Si2SD64,
  TtSS2Si32, TtSS2Si64, TtSD2Si32, TtSD2Si64,
  Ss2Sd, Sd2Ss,
  MovdToX, MovdFromX,
  MovqToX, MovqFromX,
};

enum class SseShuf : uint8_t {
  Pshufd = 0, ShufPS, ShufPD,
  UnpckLPS, UnpckLPD, UnpckLQDQ, UnpckHQDQ,
};

enum class SseShift : uint8_t {
  PslW = 0, PslD, PslQ, PsrW, PsrD, PsrQ, PsaW, PsaD, PslDQ, PsrDQ,
};

constexpr uint8_t kSseMovFull = 0;
constexpr uint8_t kSseMovSS = 1;
constexpr uint8_t kSseMovSD = 2;
constexpr uint8_t kSseMovQ = 3;

}
