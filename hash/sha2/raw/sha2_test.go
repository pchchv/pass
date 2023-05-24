package raw

import (
	"fmt"
	"testing"
)

type test struct {
	password string
	salt     string
	rounds   int
	output   string
}

var (
	tests = []test{
		{"", "", 5000, "$5$$3c2QQ0KjIU1OLtB29cl8Fplc2WN7X89bnoEjaR7tWu."},
		{"", "a", 5000, "$5$a$CZ9Csdk0HaS3TQcxgDHTwM2gwOEDCViPn83i6BpFdH."},
		{"", "ab", 5000, "$5$ab$qRq/oZkUn9lJUSIcgVT3NbpSDsjn.r137TBSoCt2kCA"},
		{"", "abc", 5000, "$5$abc$bBHLwRRW2Li0XKaX13kz/g2fkDil4Jx46aNvd.48MS8"},
		{"", "abcd", 5000, "$5$abcd$QS/LhMXxIihGHtawbvVF6A.fmwyLe5V/ymwcRAd7aR7"},
		{"", "abcde", 5000, "$5$abcde$W5y2trSo8TzQutkR2rkKOZNWkb5.R1HL8Xl1lPpegV1"},
		{"", "abcdef", 5000, "$5$abcdef$Rlu/pHRATvgAqn9Ro3bJf.ZEh1ESHNclTgb9r7gcIjD"},
		{"", "abcdefg", 5000, "$5$abcdefg$2DdlZT6BJat7DGJPj6Y2iUPenow9IrC7DFc9IhiMi23"},
		{"", "abcdefgh", 5000, "$5$abcdefgh$mnv0N8gJGuJiQCFVlADjwwxPyRiUO8rGuljjETTLqw9"},
		{"", "abcdefghi", 5000, "$5$abcdefghi$UM73isk8bmbqvGDwvoVb1d6FCC00r02S6e0ZRW5K51A"},
		{"", "abcdefghij", 5000, "$5$abcdefghij$Hohrbaiwnq1C8IvcLkwiwoIvNNABi8X2tI3emOu/zRD"},
		{"", "abcdefghijk", 5000, "$5$abcdefghijk$f5T280uHjpcYnNtXRAeD4ZkPSzktmneYag4O3nAs3m5"},
		{"", "abcdefghijkl", 5000, "$5$abcdefghijkl$M6i7lHXjEAetOBMIifrw/a8O66lffiMfYu.0RbJJqg5"},
		{"", "abcdefghijklm", 5000, "$5$abcdefghijklm$mdxEtAWpQzbySWfztql/vP3zTyZ4kPWdWJvnIpXMUg/"},
		{"", "abcdefghijklmn", 5000, "$5$abcdefghijklmn$03PjbB.9k1U5CG4E9g1k.8iBJa2rmjDrQGUnIH.n6DB"},
		{"", "abcdefghijklmno", 5000, "$5$abcdefghijklmno$r7JUILjL2Vz5.sNbeZVQ55/uYEHk6AtJUQhZJi92pW2"},
		{"", "abcdefghijklmnop", 5000, "$5$abcdefghijklmnop$p99E2fxZB/BTl9j.a2VRY5z71zEP761isnVBuiGlzV3"},
		{"", "qrstuvwxyz012345", 5000, "$5$qrstuvwxyz012345$l8P4SKmrN7jU8ToRpDYNuNim5zSjkm.aVXwCO6WuW81"},
		{"", "67890./", 5000, "$5$67890./$warGVxms4I96esLrgWuWecxitqMuUz0UUzNzOUaRTHD"},
		{"", "ABCDEFGHIJKLMNOP", 5000, "$5$ABCDEFGHIJKLMNOP$OHECpAsJdteNx4ouLLv3xuJdToxDN1xrgHLUxCQ1Ot1"},
		{"", "QRSTUVWXYZ012345", 5000, "$5$QRSTUVWXYZ012345$tgHMWnYMadERx.6xcQq9sHH3BrFXkCuIs5hkZ5N3OPD"},
		{"", "a", 1000, "$5$rounds=1000$a$h8gEN0ODxYvLokgp44mp9FQeMZy0f9j01cbNDQnD727"},
		{"", "a", 1001, "$5$rounds=1001$a$bCioE1DDKVxgfDe/fK/DEzMMMtZ9xupUa1kTFXSsA6C"},
		{"", "a", 1002, "$5$rounds=1002$a$1jMK4X/VTZWDjTD3hzLqFP.8Dvg8IIxwgZo4IO1w73A"},
		{"password", "a", 5000, "$5$a$x8ssIx34C.IRiXo29UURs5AcnNhdWP3dXGeLtS3KoBB"},
		{"", "a", 5000, "$5$a$CZ9Csdk0HaS3TQcxgDHTwM2gwOEDCViPn83i6BpFdH."},
		{"p", "a", 5000, "$5$a$Rsi04Q4ySMRbZwphTRYWj8iCLdcCCsBsGCIsTzF/nBC"},
		{"pa", "a", 5000, "$5$a$NGVApMsYEnnBZcCI6eLl2Y96f6VVWba1V5KeJRNxIr3"},
		{"pas", "a", 5000, "$5$a$GfZW.QTXt6LKucW2Z1ykqgP8WXeXLEyHkj7DOnQ2Vi2"},
		{"pass", "a", 5000, "$5$a$HdNnpOmUtrzbfREdPzizZmBeIUmiBRBmwGPnsTpAOi."},
		{"passw", "a", 5000, "$5$a$AVfXsZ8Dqyg25Obb..jbk..hJ9ukDqDgfPD.D/fC9LD"},
		{"passwo", "a", 5000, "$5$a$3xKtgp0wS8UOJkV0jmSTevsi2fZJXydQlDUrcXxMb7D"},
		{"passwor", "a", 5000, "$5$a$kdspjRhK1765HvXLxOQV2VRgiDr0tUv/8RafT9BkRBC"},
		{"password", "a", 5000, "$5$a$x8ssIx34C.IRiXo29UURs5AcnNhdWP3dXGeLtS3KoBB"},
		{"passwordp", "a", 5000, "$5$a$DnGBT354PVGNLCZ4VYS9.0qxSRqR5yipZimrzuBGmeC"},
		{"passwordpa", "a", 5000, "$5$a$ifynU6HhW0zcrnRFUzaK1HskOFL1/kERzdPwT9vpHf6"},
		{"passwordpas", "a", 5000, "$5$a$MK/aa8qQ0RoCC.GwvJsu3jBjYye3gfh85bHGDN6cue1"},
		{"passwordpass", "a", 5000, "$5$a$Q9CSYYZGe1pZL.KsvU8rCm2wNUlDL5UKMGwi4KZ/RO4"},
		{"passwordpassw", "a", 5000, "$5$a$7ym.mFfQJBrZMJRRfG.E3u1XdXd/WRFPSoeCfG13dI8"},
		{"passwordpasswo", "a", 5000, "$5$a$2.jM1eIxx0/KCI1eJtxr4rwhfzcUinEIytH/1e94n3D"},
		{"passwordpasswor", "a", 5000, "$5$a$5CBP5/5.fG15iPgiDjM.roGL58TLvPbJwmtyQoVqmi2"},
		{"passwordpassword", "a", 5000, "$5$a$6aXe9PoMbuvHBOSpy1o99s3P0xOw6f3lDZH90R3L1f2"},
		{"passwordpasswordp", "a", 5000, "$5$a$AC3YAq4d/84sa78yTIgpRpS8htNCHvwHAMCjlEP.DtD"},
		{"passwordpasswordpa", "a", 5000, "$5$a$AUSVTHrIAl8mkgcGAYscGp5stE30MVK8U6foIoS5TIB"},
		{"passwordpasswordpas", "a", 5000, "$5$a$MQJWP1q3N5ujR1ImGovShoC4QFrqwI8qdeTsnTW/2d8"},
		{"passwordpasswordpass", "a", 5000, "$5$a$WQLgeB4s/wpflgYEANXSMjgsj/1UPMJ3//vD0bObX0B"},
		{"passwordpasswordpassw", "a", 5000, "$5$a$FbIYhyxJ9dTMiIGOj/qGyFNFjhXuxg3nSOcwrc1NW/7"},
		{"passwordpasswordpasswo", "a", 5000, "$5$a$5HfML8NMx7gjm.tsOvX9xk/ci6gwl1vOuIe8NnCBR38"},
		{"passwordpasswordpasswor", "a", 5000, "$5$a$iGXe0BkVLjPmlA9qXAKqbbHyrSvFNq7KM7uZlI6ATeB"},
		{"passwordpasswordpassword", "a", 5000, "$5$a$ADoN8xGmdy5YZMOHJ4dyh3XS36n/6UorDo8ILX7/ce1"},
		{"passwordpasswordpasswordp", "a", 5000, "$5$a$Fi9ExS1OO5e9A78erBOgAJKbVShB96DTR8WonbZ././"},
		{"passwordpasswordpasswordpa", "a", 5000, "$5$a$ESOgdVLaBOC6wt59ces51MsrjcIpu6oIFeseG4erIA."},
		{"passwordpasswordpasswordpas", "a", 5000, "$5$a$OION6Mvg8cASIz3AxjTs06c.olW6vk9dP54zv9NWsP2"},
		{"passwordpasswordpasswordpass", "a", 5000, "$5$a$lRfPLEWXNjdmysZ38qUZTjvDIUyGRWCfMe1g6ODyKX9"},
		{"passwordpasswordpasswordpassw", "a", 5000, "$5$a$IA0fjfZtkWERkZYwwWeI0mchOv.0vCv/fkWIb4IQHI/"},
		{"passwordpasswordpasswordpasswo", "a", 5000, "$5$a$Dfug2LT6shmy7vuBxzP77cYrzG/OtjtG/31Mh2ncay7"},
		{"passwordpasswordpasswordpasswor", "a", 5000, "$5$a$UoMW82csgeMn2gMANJJ3MFK.sclNpANivbJoT9Jx5c3"},
		{"passwordpasswordpasswordpassword", "a", 5000, "$5$a$DGqEndgJ1BnDS3PeMqkGaz.Wu63bVglCBf1/64x2nQ3"},
		{"passwordpasswordpasswordpasswordp", "a", 5000, "$5$a$YXDTXLu7vw90x298TwlWTCysHU9NFuEXKOLs2zG88Y8"},
		{"passwordpasswordpasswordpasswordpa", "a", 5000, "$5$a$Zjc.oRVCaAcRqCOdOzlzWGbEx../OuczSKufDWVwwyD"},
		{"passwordpasswordpasswordpasswordpas", "a", 5000, "$5$a$5bfoOSohT29XbU8LW3lgDsklZf.rP6k0SvKt5k5drQD"},
		{"passwordpasswordpasswordpasswordpass", "a", 5000, "$5$a$6FI0MfRY054P3Cxc5BKx64iCwQkng0HaXgcHMq.xLmC"},
		{"passwordpasswordpasswordpasswordpassw", "a", 5000, "$5$a$xFgU8VdQxzX/hyaghlowfuIMwbplc8jWt0G2wW4f4R8"},
		{"passwordpasswordpasswordpasswordpasswo", "a", 5000, "$5$a$DJMFVNaO6Ncchn7zlEOTodwBCvtUhGLXmpBVf424Xy8"},
		{"passwordpasswordpasswordpasswordpasswor", "a", 5000, "$5$a$LxmLqMrA3AO.sFuc65kMe/4fnAGAVP2dufN1k45FiO6"},
		{"passwordpasswordpasswordpasswordpassword", "a", 5000, "$5$a$ZDsiDUZL1gUsNGWyNGKCMzAnt2QMVXIECb47WHkRKaB"},
		{"passwordpasswordpasswordpasswordpasswordp", "a", 5000, "$5$a$ibwJwx2ykaHM2GPoikj/ldCWNCIs.WRaZNFw6Azsu11"},
		{"passwordpasswordpasswordpasswordpasswordpa", "a", 5000, "$5$a$vy8UVLoVwB.68TIZpslppp/wqlrqS95Pf5tl4FE41S5"},
		{"passwordpasswordpasswordpasswordpasswordpas", "a", 5000, "$5$a$HOmJIgN.F5oDl4JcntyuMIg7VWUdhqG0ItoctTHxwT0"},
		{"passwordpasswordpasswordpasswordpasswordpass", "a", 5000, "$5$a$1SvKzMJOGkCCodx9c7Hb3zmFJn7D5U6NNcDv2XKn1a6"},
		{"passwordpasswordpasswordpasswordpasswordpassw", "a", 5000, "$5$a$XGUrQNPp3aHzUHjWKWag1WPm.bT.uGXohjJQX87Y9RB"},
		{"passwordpasswordpasswordpasswordpasswordpasswo", "a", 5000, "$5$a$KpfsxhqWavFw3Y.zDiVQskgsgQBO9LMTvbIqMU.LPS3"},
		{"passwordpasswordpasswordpasswordpasswordpasswor", "a", 5000, "$5$a$pYJ/Ih0MLYKjJ8JsF5XrJXDA6C6Ey5aKw5pMSuQyLA."},
		{"passwordpasswordpasswordpasswordpasswordpassword", "a", 5000, "$5$a$FSOEL7KkLAsOrMW8/6qdW95lVE5SzftNw8kvFgvLZW0"},
		{"passwordpasswordpasswordpasswordpasswordpasswordp", "a", 5000, "$5$a$U4CAjSRJEyQKUGUcd6LUIoYOh8PIvzCUmKUhhFc4qX7"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpa", "a", 5000, "$5$a$Bw.mc9gewl8Bv8YVP2OAjr1b4VptK0Z/6ngSeIt00d8"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpas", "a", 5000, "$5$a$as9mpD4oZJ45D8MigUqtcZyNg1PtAw2zfa6xDtm53l."},
		{"passwordpasswordpasswordpasswordpasswordpasswordpass", "a", 5000, "$5$a$dy0bt87jdooWdr1yBx4EylgtRpckkwioxPCczgViZj8"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpassw", "a", 5000, "$5$a$wa7KwS.SI3rX6zy9PMjlSUt7iSQl9FxeHcR6Q4On18."},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswo", "a", 5000, "$5$a$5xz9kR3L.cRN2HO6818NiwfNfL2UrGUvE2G1XM09Tr7"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswor", "a", 5000, "$5$a$7t2FJYlFYcs0EWBjDbOOIecnbeZ9FCxzkjEuLZQAq6D"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpassword", "a", 5000, "$5$a$l5ak/wtvCH.t0nzD76gkqo53xXjQhaDVFXOIOfBWo76"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordp", "a", 5000, "$5$a$TmQ3d2DZDP4F3k0Qg4hzLjUigtWDpR8G4MKyscQmT3A"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpa", "a", 5000, "$5$a$rs3RBXuiFxN7WtBOK91z/1Dzj3HtwbXfF/cbG1KzBeD"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpas", "a", 5000, "$5$a$aDXAPeSLOV/frmuMhDDxQaI0uN0XyWmt3JIM.fVsNfD"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpass", "a", 5000, "$5$a$3YzMxqb.xRiaPJFp3YwWo8f7r0/lIj84PvjVVN8BIY3"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpassw", "a", 5000, "$5$a$ku/pr.KfD8xEZee/t5rpoCyolEbEJn2BVfRc1Am9xO/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswo", "a", 5000, "$5$a$S1UjlBKykqg8ORL7c78PFAfLtwOpo63f8jo2JLuJZuC"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswor", "a", 5000, "$5$a$TgCskPPq6Px8if/orkdw.n03K1lkZtdnnGx4cYnKp1/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword", "a", 5000, "$5$a$BjoYXDpjTvzlqtdEHoykxXVV5v/Xgs8MozCtGLopM.0"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordp", "a", 5000, "$5$a$i3biI/0rZ8f7/29SKGkLzvv49yU./3/gJIAFrZSpC7B"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpa", "a", 5000, "$5$a$9/JmGanXN/3/SLRwsUMMlN09QPX92zyFB.mvhLDxU5B"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpas", "a", 5000, "$5$a$kCpgfUwpaioM791mWWUFRkAf.Fs2Hapl/Ab352ptZj."},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpass", "a", 5000, "$5$a$1X6iw/Ul2DdtYkMtZeymMNWD1va8Lmv3.dCXLlk2sx2"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassw", "a", 5000, "$5$a$ijIZ8IGcQTZMzfavUpa6o43YYLCZhl2APwN3UJzYxl/"},
	}

	tests512 = []test{
		{"", "", 5000, "$6$$/chiBau24cE26QQVW3IfIe68Xu5.JQ4E8Ie7lcRLwqxO5cxGuBhqF2HmTL.zWJ9zjChg3yJYFXeGBQ2y3Ba1d1"},
		{"", "a", 5000, "$6$a$Z6IPkDduHdwavesVY2NFMpOHkigshxPYdhfLg0D3A7/XFQcso9RV2E8qczyJ2su.dj6RRLaTpvgwN1rZfK0I9."},
		{"", "ab", 5000, "$6$ab$xnh5Qsr2NdbFw1PgdZie7nLON3gv.S.23iQDBqAzkdoXPtDnVSpludXkM5UWybQO3OI7hBj9wHg9Ow6sUWD60/"},
		{"", "abc", 5000, "$6$abc$mJP3a6FyA8uCnzRtlnNypPwjnvpi5TP9qOrInzrfDmwxUQG38PkpCPdqfTb8JQfAngapMxeim4AZ..hSdRRzD."},
		{"", "abcd", 5000, "$6$abcd$NU/C5Gju0G9iuhwYGc8C4T7UNm5gyOGf7Xo/YAAExf5aQb28mUxIL2q/EzSmLYbkVO9uOhSV40MbPwn7aHHHz0"},
		{"", "abcde", 5000, "$6$abcde$Lhdc0UuwkjZ5DQ/53BLdYd5GUrFucLIkkGfkueqGsc4oZk0fSB.lW5HNJpH3Ylz.L0QzyqfrhFBNyw3xPs0Lj."},
		{"", "abcdef", 5000, "$6$abcdef$t8zWbEvsAsHfcR0cwTk7.B4mfyeBTxZLDx1BAyR7l78H89jWjwb7da5RMFOTqy7lod6pRidfXKxEJO8PX.PYO0"},
		{"", "abcdefg", 5000, "$6$abcdefg$11VEP0wJAS.aNv1qWIR.Wqn38LpeUu5GpYeIj9UGfCDjlserGN1BRdkqMT23sfc36KUYON4xKPFsNBtxLdp0V0"},
		{"", "abcdefgh", 5000, "$6$abcdefgh$v7sYNA18/BerGOYQLppYLyjH4yJilp8kqe/ef3KYMK9hOIdzH1yzcmP74Ay.m51y1jP3QqxM7Jl75S4CxDhBq."},
		{"", "abcdefghi", 5000, "$6$abcdefghi$N3CEZsJRV9mbISNV5Fl6FFwL8RYkDymKraZl/wxIwD6ipErfVOTUtTkeOnNk9KwglqBRZBEe5QknOoj4HqBHW1"},
		{"", "abcdefghij", 5000, "$6$abcdefghij$7T7df8XBkLMdUu88CTm53FLArDdGmq/nn55CVn9CMt4.MJaFsXu6CQpbmL9UbX0J.C3AX1MkPKvniLL00lAMz0"},
		{"", "abcdefghijk", 5000, "$6$abcdefghijk$L5InIoA.tWhbxByZZU8.E5/ClRCvPvnD/MpP2Fw6eqviqMrAe5oUp3GV4SOIU2fzZJl40dXJFQlpiVkKUCx/C1"},
		{"", "abcdefghijkl", 5000, "$6$abcdefghijkl$pQPK74I5wapdxPf8YWA7pSPuRWmXlI5TbyoI0EK.AHnXx1IZMdT63YUbcHUfjd9mgdWZKLo27sOGTzziErT9Z1"},
		{"", "abcdefghijklm", 5000, "$6$abcdefghijklm$f.v9oOchLiuGYhky7QA9AOqMAmxKTu9iRQmDtn1XWI5mHPvakQUSKJwISf3DEyqCVAX2gVXg2OxqBFKnBjMcB/"},
		{"", "abcdefghijklmn", 5000, "$6$abcdefghijklmn$58TlzgSuzWsAYj1MlhCVtcaEb46PIqS5LEVNFE3Rj1Cn81w7.GnVz2v6jhS4otit9C1e2nojtE9w04CLEqmkj1"},
		{"", "abcdefghijklmno", 5000, "$6$abcdefghijklmno$IuhBzXABLOkV9Iw8epw2E9tIjYVoB7QY1BQIfjaPA5Dm0j9vVBLatLWHlTF0Dr27XctYrYavSRFZBLece6NdP1"},
		{"", "abcdefghijklmnop", 5000, "$6$abcdefghijklmnop$6.vC8ffobuN7AxcHvesxeeksF2DXFfpYyFt3PFU8pYpEQPhWFSN7hwaUQRfHg/LkfB3jIPEitUcU7ZTqjaQUp1"},
		{"", "qrstuvwxyz012345", 5000, "$6$qrstuvwxyz012345$nijv4ng4T0nplrD5Odbhy/WIWjMxYOOfVeatWJn21RsKHpx1wEwv5lJ6bxcRhAZUkGlrXMIYJWFcw8.7vS0Vb/"},
		{"", "67890./", 5000, "$6$67890./$RBwYm1yXiNS03qj/NJuXVKtMZTswb9X6ooUeD3te48jhm2/G7RLrdshz3ni1hE.aPQ1SUJcTMPo5LKoyq1.FW0"},
		{"", "ABCDEFGHIJKLMNOP", 5000, "$6$ABCDEFGHIJKLMNOP$hv8qZhuzMVc0IFBbNgS7.IcohKodUTGf/LUI79ky5NJZbB4wONSS9spEq/roD.WWO73zAFUF4.bmsJRaED0L/1"},
		{"", "QRSTUVWXYZ012345", 5000, "$6$QRSTUVWXYZ012345$zCTwxSLN/2oO9U17pELyZJYdLPAx0d6VlDFIs5fSllerpTG9UXzUG8yzefGh7Nn3fYmYnL/cRkd5Yrtz9qs2h."},
		{"", "a", 1000, "$6$rounds=1000$a$q/ZSdy9IBSzcpbaIjdRTOu569QiYiP4n7Ab08Oq1Ir6J.GD1xR3BAwRIYHnavtE1Wzodknd9BxknlHhFBP/az1"},
		{"", "a", 1001, "$6$rounds=1001$a$1LgZTwgZLXxTQ4YhBC7mzpSbPbXwOMjOQhAP6D6HlIk5CPMWt9eaLdwj70vgjAd4wtjWJERgdMX27ED5phxhe/"},
		{"", "a", 1002, "$6$rounds=1002$a$2K6qlumdpbtycktydOLKQgsyLxUlybgOdZZEBbLhXghjr3fNSW/4AKvCXDs2e9IBZkCGFJH6sYNNMFG.hcJSr."},
		{"", "a", 5000, "$6$a$Z6IPkDduHdwavesVY2NFMpOHkigshxPYdhfLg0D3A7/XFQcso9RV2E8qczyJ2su.dj6RRLaTpvgwN1rZfK0I9."},
		{"p", "a", 5000, "$6$a$2.GZ8yudlr5SHiCPkX5N4O16VrDiQ2OZrbwWIoAlxZVHQFGoqZP6JY4XB1c.jTYlVXS7wOdfIg7aItV3orkit0"},
		{"pa", "a", 5000, "$6$a$HUuS5tY/wnt3E8eDFp/8JPTIHHJWvX37gpDXtpDIxWYor.jtUu90mpY7x8zCGFDsnRKMuIy0.BJC7K1ibKhxx1"},
		{"pas", "a", 5000, "$6$a$g5Q6aW5iqQYNy3wQFOl5cJ7QhA7wsrK765cZK7IzcYg.UsWSADWdkr3X3cFttQPoHnf6eNWSPeRVm59BzO6Fa0"},
		{"pass", "a", 5000, "$6$a$wQrz9ymkqnEyACDR001yzYLlAL/GtICZdnh4j5dTlGNtqc/9FHlDDIoS3v4z5x0I7EXBt2XdNPO/xIW4LYxtO0"},
		{"passw", "a", 5000, "$6$a$vGvPPKUaIa/1Osg.IRyUTPs.AySaBCmwnHinZdj/ikwgFc3xzhpnfTmi43/ZYxtz5xs.pTQf9Xb/yPmzdVTXt1"},
		{"passwo", "a", 5000, "$6$a$.fL3fsn4RwvmlbedPXIEEg6lmJJm/EfDGNSEYud/rlN62bTIbsLhtVqEXUxqMiuPIzuo9.7O91mguOrF7JMjo/"},
		{"passwor", "a", 5000, "$6$a$SFYSJqIV4xSJbYeBNuHaFz8ZtDjv94BBTE674Lpu5UwC3EZerkqluIeL9tRGE8IQDFTNh.4nugIBNliUiMcy10"},
		{"password", "a", 5000, "$6$a$cDF29/4rxkZzke7MDbxA5QugGKNXjz8kkJgmZT.KmMruKzBbS9DbFa09GnKP6G5OyNipfZwCBHbrAJRPb5aAR1"},
		{"passwordp", "a", 5000, "$6$a$d1UzpJNuUZGOszAQcMZiJhPM2.oatkvFbdwaq4L/MuDujM7ADfjiFcxxOv4XkICpM7OV6AQq0EFcro/hokJ3c."},
		{"passwordpa", "a", 5000, "$6$a$0ZQEqjwKwgSy6yYb3hVK14ZT5xBVOzXzDu9Wsfg7XG0UsZBbqSq/ntsy0jS.m9Q6rQ1C6qOAhZyeokwMhwGkL0"},
		{"passwordpas", "a", 5000, "$6$a$jpX5MXO9Ihh2ud9Crs/RO0v5mMaMVyTdK4fMtTJT7wDN3y1QsVNd6XQPjtjyhqoNf6U.17uWJEuqE2EwQUjy2."},
		{"passwordpass", "a", 5000, "$6$a$u8v6VyZMYcXmWvnM3qwSLFyj27OxwCJX4sWeWuoe2NszlwoRq02cAxGdBqv5QT8qCHdVaAodsZSCJVeOOSaaJ0"},
		{"passwordpassw", "a", 5000, "$6$a$C0Lw3KsTXF3v175TFrBSPKZNQUyGvYK8Sxm5i0gxQq1OHY9zzS2bCNT5/25M5zZYKFBa.5YBqIj/.lLyUyWiH0"},
		{"passwordpasswo", "a", 5000, "$6$a$FEDrJkxmbByetjs2HvUO6DdQHnWXhgS.QVBgn.lk/t4hwk2IsLghfsBOOAizbji8xCE6UuVM2dhD/RJpWey2T0"},
		{"passwordpasswor", "a", 5000, "$6$a$paYanVEXJJLnxrsKQc5VWLz.GVfdi9yLoMyfmZ92OwtS.gubT7AIJYFv6uxIR0/X7vnsUb9X.62N2/KGq7STJ1"},
		{"passwordpassword", "a", 5000, "$6$a$w4jBmtZlVA/16NIE743sU5QyJ8BPYPIMBxSpVy1G6KjttDQt83p1oKmwLBp.U4ttvg03hqk/qCw2VD.hEi6fR/"},
		{"passwordpasswordp", "a", 5000, "$6$a$.nQPXAfCa3wYsL6XNUL13Gx.zBPOjFaggIdy4bkC6VJRHVzUnL4UOFz/L/3OyJSmucTeZASIq1r.9AEioKvrb/"},
		{"passwordpasswordpa", "a", 5000, "$6$a$.mGONN21Bxx/mLRteEFjQUNBHhxea1Zghgz1hi.lgr89i79plEf/yWaEcOmZ/jE1n/NMBqyGxl0NcgqTIp4hs0"},
		{"passwordpasswordpas", "a", 5000, "$6$a$Hc1ZpGLw6IftPnNzjofWdNMWYWhKtAV.UDXbBHSkipb0Uv4NbWFggKGJgfHAEP9ZDa0KmJV0e/6FvKqvXDcnN0"},
		{"passwordpasswordpass", "a", 5000, "$6$a$OoesF5Px43ePkU1oKhcsEvg21BH5JxMQTu4FCK9CwhHkr2ges9Wm7IKYYvNILcvxmMnH11nO1Tab7LlpMXqjB."},
		{"passwordpasswordpassw", "a", 5000, "$6$a$/.bOypOhoO7NkxSwepGmfREqx2F6x181xLjl.nk7zlJj.OpROQVqV2ldZAc5vp8NxkQb5NBeNGE0wcKxEMZYM."},
		{"passwordpasswordpasswo", "a", 5000, "$6$a$l429mIwN0QMyuKv8el1pvIs.E5LXoO8NG1vHt685HeRP32GZfQ7rrO5UQJn/iihog3pThh/XEBUZ5sU8ll6hO1"},
		{"passwordpasswordpasswor", "a", 5000, "$6$a$o.0oPvgzTDLzaevEzmf23fCQ3n2ovgtIUZuu7zZjSTF.xzd61L6xfcfsae/caP0jSI2SYyt4afdnofe2zM62V."},
		{"passwordpasswordpassword", "a", 5000, "$6$a$ht/BgUA3Tr1tI8tnRITvibn.rXQ6xjMAXK7bC0bBnK.axJ1J2gVcVyo8vw4pdcm7dDr.ICAxvKSfYnYEPZubG/"},
		{"passwordpasswordpasswordp", "a", 5000, "$6$a$dmbpWylbazJLRY/5kD9k5tIrXk8ZGWvc77CmvSibybc54wpazLQEpSYotQbGFARPRfD8yVhdVNnsmtnQfW7qh/"},
		{"passwordpasswordpasswordpa", "a", 5000, "$6$a$ztoxMY1332MdieRrRCMFXVjxnbhk7wtTDq/MosYcun2wwQSZ9gLlUSbNDTtQ.C9Ns3ZroCWkoAkAhL3ga7Of1/"},
		{"passwordpasswordpasswordpas", "a", 5000, "$6$a$vOcIXCqao40l.MsjsylPdFE43ibraEui21r8obTvy64t61meMD2kzmrwEJpdnxO1/linnmmynDuFzfX9bdQfL."},
		{"passwordpasswordpasswordpass", "a", 5000, "$6$a$rdlSkCcboGfx8MBmmQvgn.ASjHWgLV7dQhuilN5s5GAjOt4lji4lS3R97nFX8tRrEX6pnjsaRqQYyw9a83p4G1"},
		{"passwordpasswordpasswordpassw", "a", 5000, "$6$a$JqofGDjZIjTEG9sk3et1UGklMiS9cFdv0cNrJxVuc5Co6iHGFjxH3LACATDRq..7LIURoFOxIg84iQ6n8Bbhy/"},
		{"passwordpasswordpasswordpasswo", "a", 5000, "$6$a$li226SSGj.Zl04Qrv5gLazUd8Q7FC79PKZ.gskys.RVxRWhCqbeswwxjdFkeNT8DeB9yMV7ObweIRXLU6/vkI."},
		{"passwordpasswordpasswordpasswor", "a", 5000, "$6$a$bte09FK2Zt4vLXVKepQ2L077NMr4.uheBNn0F8Lq2WlTUthyW1uV4jMfqllxrGemBxEGcSxTC1kwibE3WEc41/"},
		{"passwordpasswordpasswordpassword", "a", 5000, "$6$a$VRT5yzDrtRfQ3wJx64TZlf8SXuJCr2zWYAfUvSLQZQqh/Ubdv71P.LMVNLlCaRNvZf1ay6QjThUQJyvPj29sW/"},
		{"passwordpasswordpasswordpasswordp", "a", 5000, "$6$a$NL.wqM1nYkpaeNgUHqndFARbSiKJTfzOFAUBhiENtHtHWaMMflnk5IThT3KWIVa3rnQLDDkGOOgqbHSH8FDbU1"},
		{"passwordpasswordpasswordpasswordpa", "a", 5000, "$6$a$2Y55eiAzLHJ951TbHmfpuwFQiE9o/4dxsns5xRj.RI4Nz2DOCh0Afv7DV2/ASAXXTUvL90mO1VuC5.GovaQDZ."},
		{"passwordpasswordpasswordpasswordpas", "a", 5000, "$6$a$UUbMzedAQ0OrOWi.iHcmH.x9eQKpQDau35bHv5mLtX07habgHpMChhFwywWFm0QOztEUUrbfDCmNwqCpaYw561"},
		{"passwordpasswordpasswordpasswordpass", "a", 5000, "$6$a$VBxf35WZRhyIodRreS6EOEb0mUge4.s/u1CN2pmq7GkmL9V7CbpmY7PLNtMFEwOADyCHur5Bvs.FGQmogQuf91"},
		{"passwordpasswordpasswordpasswordpassw", "a", 5000, "$6$a$1Y7DqOlzQP8bFRlHagWHsnhE8NVuCuIFDLlSq1hB280wKC6fEK7iItr7/P6LwkMN3mqVHuQMHigeleoB1V/qj/"},
		{"passwordpasswordpasswordpasswordpasswo", "a", 5000, "$6$a$YPO0cEt8GcWu5p7.78dSDnHwLSNAaNrCJytQM0O92UFObNssXodhhHmNRNQHuIIJsamDpZo2fenaRNFqEdXoo/"},
		{"passwordpasswordpasswordpasswordpasswor", "a", 5000, "$6$a$CwhkFGAtkg9.ey9cKXcb4LA9Q.xviUgiwmYD65NTE1zV5Fk35yMhTggSIUjwqMBFjkPOT2CoaD23mY6mTF0n51"},
		{"passwordpasswordpasswordpasswordpassword", "a", 5000, "$6$a$vb2IuTylTVRiKzUCoBAVnR78V./MN47yYDkTaZXGWLKIElFeDUnkrsOAlCegKjg7gHyY9LQywy/gyVYU.D7cI."},
		{"passwordpasswordpasswordpasswordpasswordp", "a", 5000, "$6$a$XIZXatmyFVhAR8tUGa72Frt/G9u4QoVNhBF5NM8ZN7i3JKARdYVujvB7GqbY37Wve5rA9tpdgCGpxwhtNMpaN."},
		{"passwordpasswordpasswordpasswordpasswordpa", "a", 5000, "$6$a$WmOPLnHF2wtm0/mLzNA8BmVxJlRFSmmXyl.Wnz89b5JfFFfyldELGa3sFL0LFcupaHQUvVw5QMXRgrPPEGvMC."},
		{"passwordpasswordpasswordpasswordpasswordpas", "a", 5000, "$6$a$QZgDm7odB/xtbf/x5AmI6x9DpWYqtApEGjIPbkxcEC7G25Ibn9plQdqlcwBnwGROwRpVS8zl95yCL4C3t2buA1"},
		{"passwordpasswordpasswordpasswordpasswordpass", "a", 5000, "$6$a$Mh.pluuvGbDSTZn9QNrUYWq8Q8mUtRX38S7uQeccvbdNVTG.e62NPKrgjM4JzMgH.7mWmY4VOyLNQOtH.Qbra."},
		{"passwordpasswordpasswordpasswordpasswordpassw", "a", 5000, "$6$a$VTfS6BpurvR35bGVaiT5aQebuirXM7u0C4HCHOWmSypujiKNHdFb/VIU.IRFa6luGxIKKhpPRfkn73L9zDLJl/"},
		{"passwordpasswordpasswordpasswordpasswordpasswo", "a", 5000, "$6$a$RrtTJpOtdckHPIIG0utYRVLboamUYAYbfjVBuk8.qQHrZ.I6GuHIIrBWd7pdguSaY1QEHRvUB3BLeO8uT/Bh3/"},
		{"passwordpasswordpasswordpasswordpasswordpasswor", "a", 5000, "$6$a$J9zm3yZNN5x8JchIactr2R5WJ7epPLH/RyajLg0v3jlhJLjcYE3wEpCPIVl6xksaEdLhzzaYom.Elk/A5oUla0"},
		{"passwordpasswordpasswordpasswordpasswordpassword", "a", 5000, "$6$a$vr2buLAslLFlLPQzPVAhQDidRVz4YnyTSSlWUVo9bAznxiK7dcimCKpOt/GRA6h22FekXDvH4vADiXTJIOH8v."},
		{"passwordpasswordpasswordpasswordpasswordpasswordp", "a", 5000, "$6$a$RrNNFkr7wxVo4jeUV/LZCugv/cbvBYJiEh9WDXDLnYikSI/uT3zomN64ZK7yz.DcDhFRIXNFz9vQQgCqk7yp3/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpa", "a", 5000, "$6$a$IrQjaHvY2nSgmIrVpRSAbKf2KwdR.Dr7wXI5aen5BMcwCNbI91nuMYtbGvT4CAFrTvYtw7HlN04sZud16oK/50"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpas", "a", 5000, "$6$a$QXsxgPhX94A/JY/ysc3/6pWmqkL46dgniKePmBj/NWdo8zfQ9H/vXe6A0DzPKPsJeG.eqavXce5ULcS0tmS57."},
		{"passwordpasswordpasswordpasswordpasswordpasswordpass", "a", 5000, "$6$a$Mi5A3/OlyZCNy/RlsqufrkNrODVdLQ00y4wMid0dofzvA5Xdc5rwl6e/IH0ANT.8M4LQ0EnzTaoiaH07Y73yu/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpassw", "a", 5000, "$6$a$ShmrcfPrK78J4A6yeBfpCBtPaeWj47YPKDktwVHeKv7A7jU/RQPtGfy3gdScjYfwTA/wh95yLTAPDv1Vk13LU."},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswo", "a", 5000, "$6$a$stWiOqO6J/bOQVkhe3mm5yS3npGU5fFpSMTghQeZNRr/czzh3Nxvg8HGG6JwjLBZbvU4wigYjOrLOMb5xSjXx/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswor", "a", 5000, "$6$a$6JtfKJTheuSyWkjuIGnm0LlRoI2ZltBaNu6185XWVnhUXb.PRYIM5kViLGK1sYCamXo.UsNzmfDkfda4DgiFQ/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpassword", "a", 5000, "$6$a$4/GynY7Nj6x0M.kzmzQF72YfnP1nRJTm5eZlXqap7EETHW6r4eSas9SEjoxJOWjozECjaJngvYIvBxInjPlvc."},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordp", "a", 5000, "$6$a$KFf/SJFiyGGvFMebABD85umh6UKsDFMCOO1F0CNHwyiyQHWRWe3LiIiCysfCCmQFvx6RVv8TzvOd1NsYkkk8Y/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpa", "a", 5000, "$6$a$ZvE9/pfJrvzl2hLAotHm7b7LA.yIHv6wiIvQwOstSr1/1X5jW.xEC1UY7b5zrELNNp7eMANlXDfKFmfCZHU0f1"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpas", "a", 5000, "$6$a$VI0xoGKgZoMgjXIflCIU/GeU1nbd1tAj97efY9W1bt8uT6sHPDM7SJO0rVZqv2wzAioljIf6mRYvvzkggxyq90"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpass", "a", 5000, "$6$a$2xOzg2n93SZWeYbqJNKNgMngkSvWUKovpGUofhLr/XLFd45PS1vieHlSO5WH5Ok3Gs5nSblUgvTqRJEGDgnZ./"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpassw", "a", 5000, "$6$a$hATpzgscOxHuvWtEgPxcEHBruxhGXAzXR/OY/3KymoSP90khvc6YJEA5RuyTwLHSgJUfnppQruLi7l8hQ0lLw0"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswo", "a", 5000, "$6$a$b9xZTbVSCBG.3yO1b5sFiUYwI0FNo8CXRq3md/.17G8whmQhUe33Z3g1Zy460VvwjFNeebFySR44Icl7VF0zn/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswor", "a", 5000, "$6$a$soVtpRYFRKH0i68EXEcbq/KbrJbuKQkXAzw0zCXjshVoamGb6CueGq9zWxVQbsD9l8it5CLugR5r9vwGq/CMe."},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpassword", "a", 5000, "$6$a$MXusFpDMp1x3gwNM4gP0GQCghEvml1nFMvtXAdYa/i9RZ1Dfbn42sXXcS9/g3nYJHrSgbSVpJQ.G/RCb1ms8I0"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordp", "a", 5000, "$6$a$92E53ObvYVFDERKnb5wMG/20A6pob7GEp./LoefiFURg8wA0JIXJM60/vTAR0a0PoRV/aiNpVLmMUsDZiDUFF."},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpa", "a", 5000, "$6$a$iUTCg3PequYS6S1NMA5VPze8knWY.sO.BLy0sYWCV1sOZH0up3QWEKa83V8PB6ZCf4j7DOlkbtF9wBXxYYm/N/"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpas", "a", 5000, "$6$a$wGCgfgnBB9vCYV3GK/IMCijtORGJphRaB6ecjo9pHs9kr6rhFhhYyUFOloDer9bhSz5Ar4cLwP6k4q/NGdoql0"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpass", "a", 5000, "$6$a$GqCyixlbKI9iUMz4G2oQjqcI4EerTFDvIwvdi7cU.Fmkf5q8qxIbwJ8blyB.BEEbaWlZM/Iq.APTtUeOPxN/01"},
		{"passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordpassw", "a", 5000, "$6$a$tszvYONTDoPoA4xJLb7O4MsxO2wlmXWYGMsCyQ0bjhMtfbQRhWAkBVBVCFkjAkq3tr8S47P.jvW8SsHxSUvK91"},
	}
)

func TestSHA256Crypt(t *testing.T) {
	for i, tst := range tests {
		fmt.Printf("%d\n", i)
		out := Crypt256(tst.password, tst.salt, tst.rounds)
		if out != tst.output {
			t.Errorf("mismatch:\n  got: %#v\n  expected: %#v\n  password: %#v\n  salt: %#v\n  rounds: %#v\n",
				out, tst.output, tst.password, tst.salt, tst.rounds)
		}
	}
}

func TestSHA512Crypt(t *testing.T) {
	for i, tst := range tests512 {
		fmt.Printf("%d\n", i)
		out := Crypt512(tst.password, tst.salt, tst.rounds)
		if out != tst.output {
			t.Errorf("mismatch:\n  got: %#v\n  expected: %#v\n  password: %#v\n  salt: %#v\n  rounds: %#v\n",
				out, tst.output, tst.password, tst.salt, tst.rounds)
		}
	}
}