#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int NUM = 128;

char array1[][20] = {
"yanSiTxfG7bmgRFL",
"NF61VktkskDqC56x",
"qSaJgJIIEdUCpHoy",
"QJduqV7dbTXAKbAN",
"DnW__cH7OcVmeWg9",
"Q335G3MWiUszj6db",
"kxS8m1eCkIdVeHRf",
"RHVNzvB2kgebtgPO",
"s_8vzK2hAyQBtiWE",
"zNHk50yuX30ioPWs",
"oLonimF_DUL5cOkP",
"RJh8xYhArA0FFP6B",
"iaQufXdC3nvPU9TC",
"GegAmUYNwdY_hSaG",
"E0LPnDWoREnZaa4W",
"fgWy3tincQbOEJeU",
"6pm9uO9i9F0dKCIN",
"zrD1u99H65DvCeaf",
"Q9SnV1KpOLqDviJP",
"mCjl0jcR7UmjtxJG",
"McjxdRFOtfZjoxzE",
"rnqNd_urrhPeAmdJ",
"43wICzr8AKUb15Ys",
"1ZE_hLaHtbu1uMV6",
"qhEIENheXSyc2hxg",
"5wO9cWMenKtWbMyu",
"IFSQ0zCo3OIfMQ3a",
"Gd8YzXug8WYvNfUE",
"0kY2IcMcBr_vooMG",
"kxKVS0aQyyO22wsR",
"TqEKF6OD25J2qjFC",
"Rc6EqKplztNsTIac",
"W9OHpcj6sPMzlPA8",
"5QOdodxXrGOmwGc3",
"xfvLtavKB1Xs48ly",
"bwRRpnV648Nhudmu",
"a9IZJPEm9_w43y0S",
"xCaevJEEhafL1GHT",
"uBYIKK2UqDoMgesA",
"GbOjQSgrVu3OJxNz",
"z2_Xv5tQrPYdioIg",
"JpSB2iDvQbPMP5Ae",
"zDEDAFOZ7X1p0FIx",
"IcXNkKujmoWIQBzd",
"cYidTTas3ZA9FBFQ",
"O7iRYw81XMR2ZgCk",
"pQ_hvvZXQW5Bsvig",
"EqJkXqLJmkG43S8q",
"iflD4yzujO5UmCaR",
"K7jH3gUDF8dEsa6y",
"4pKep6xqN7HkalRE",
"99gHbsGAKXTVb3vn",
"74pFU7iSlvTuG_9q",
"cEn9HSdJdVUcMtbn",
"zEPi7U0Kn58q0LUi",
"MHAigFQsdimvqvjN",
"kurj6c8c9KpPATr5",
"3QouYuSYhxAa8fnS",
"kUQB58k7AqGy6RHX",
"HpEdc_OBxEk1u0mC",
"ud5ovdFDCi4WGXYs",
"D_sAmqBvFF8z6Rsi",
"gI4NEQKqFeNNBRfG",
"BPSQHlJJEbQR0qtF"
};

char password[] = "_34qx9RlP2BWtEIJ";

char array2[][20] = {
"ip4ayfyuSmt6uxbm",
"NBhZl5lzN1NdbmXS",
"xYj1AjPMtCQJk1Qw",
"MdR3TXVmuxVMqS96",
"05cWnkaWhZK24VAR",
"D3Z1Pp80mkhKEezf",
"vKdQpgn73zV9_Iq3",
"boOLV0yTatE7UBKx",
"OG90AgN_PFuHcUZh",
"TlOVKY95y4CKU0Kq",
"DShOYbMKyjeh0hZZ",
"eVuO15UJxijBZdN3",
"dk58524dXtSIjhXX",
"rqVytvn29lJexV_3",
"JrCFQC4GlvcDKp76",
"Co6WLg9jidx3zRor",
"EiDjnMfVqC35FoPX",
"_rGTcSwulgWyex6h",
"p_7ru5S4Vak3XV5m",
"GHPpk_pMqSUC_4NW",
"GIf9OQAXBiUvRPh5",
"1p8H1AEdJVbnxyvh",
"wnkLkWRMvikyqukb",
"tCqdOWvels_wmdl4",
"kxv_yDeIfHVP9HZ1",
"ONCJoiAl0FMDbZza",
"xRiPyou_Rr2PnK2J",
"lvIi8TrHqmFHjAEK",
"UH5VkQAPeggjwbkV",
"5eBuJSHBNASrIr_Z",
"wLtFd5qNNk6pMMbJ",
"XL6Yi5pc9mOGMVh1",
"hrM1SNzorV6fTitM",
"Lv7XSavQKsc7EnCS",
"voywslKD1eVPgjFn",
"_GIbhnrlDvBGU9hk",
"tKFdcKQWXZ4zIJI2",
"zdFu5xB9rQM_hkvl",
"qGhJBESxbemAe51V",
"xOqbX0_HbAunOvdh",
"0h1N33F2nG7moboe",
"J1ZxcpnSIaLA5HVC",
"vFKx0728mRN8HGJ3",
"ZcND7_nX5cKh0kL9",
"XuJiSMA0ONlPA0Oa",
"X0r4Uiev_mRonl3n",
"XL9F7KM_Q1WYQ7vY",
"davk481JhjoeXdsE",
"goOL4ke_3vZm_78E",
"M_Bk0YkhelkZVRKi",
"x894T438OauSD7IK",
"uC4Fq3kLWfJxHWX8",
"hZqfZDHqo9sAiJPM",
"9Ih0nHJ_xBtjAIWS",
"3Tv9TzDxdFa4q_34",
"HNfUH760csv1_xOC",
"diG1hr7N_RLGPI5h",
"zMVKnc0CPgPawbdW",
"p3Y6okbEDF94POvk",
"pgsDDrsRPmq3PNbj",
"JQdcbiUvl0uaaDir",
"BM3WQMumaB_xisRa",
"zHgW1BdElEkli9bl",
};

int mystrcmp(const char *s1, char *s2)
{
	size_t i, len = strlen(s1);
	if (len == 0)
		return -1;
	for (i = 0; i < len; i++)
		if (s1[i] != s2[i])
			return -1;

	return 0;
}

int main(void)
{
	char *text;
	text = malloc(NUM * sizeof(char));

	printf("Can you guess the password?\n");

	memset(text, 0, NUM);
	fgets(text, NUM - 1, stdin);
	text[NUM - 1] = 0;
	text[strlen(text) - 1] = 0;

	if (mystrcmp(text, password) == 0)
		printf("Congrats!\n");
	else
		printf("Keep trying\n");

	return 0;
}
