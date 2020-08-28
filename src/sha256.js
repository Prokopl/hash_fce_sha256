class MySha256 {

    /**
     * Pomocna funkce pro rotovani doprava
     */
    static rotateRight(n, x) {
        return (x >>> n) | (x << (32-n));
    }

    /**
     * Funkce pro hashovani do SHA-256
     */
    static hashIt(inSequence) {

        // inicializace pole hashovacich hodnot
        // prvnich 32 bitu zlomkovych casti druhych odmocnin prvnich 8 prvocisel (2,3,5,7,11,13,17,19)
        let H0 = 0x6a09e667;
        let H1 = 0xbb67ae85;
        let H2 = 0x3c6ef372;
        let H3 = 0xa54ff53a;
        let H4 = 0x510e527f;
        let H5 = 0x9b05688c;
        let H6 = 0x1f83d9ab;
        let H7 = 0x5be0cd19;

        // inicializace pole zaokrouhlovacich konstant
        // prvnich 32 bitu zlomkovych casti tretich odmocnin prvnich 64 prvocisel (2,3,5,7,...,311)
        const K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];

        // zakodovani vstupniho retezce do UTF8
        inSequence = unescape(encodeURIComponent(inSequence));

        // predpriprava
        inSequence = inSequence.concat(String.fromCharCode(0x80));  // na konec retezce pridam jednickovy bit

        // prevedeni rezetce do (vice) bloku o velikosti 512 bitu
        // retezec se sklada z 8 bitovych charu
        // vysledkem pole sestnacti 32 bitovych celych cisel
        const len = (inSequence.length / 4) + 1 + 1; // delka zpravy v 32 bitovych celych cislech + jednickovy bit + prirazena delka
        const numberOfBlocks = Math.ceil(len / 16);  // pocet potrebnych 512 bitu velkych bloku na uchovani sestnacti celych cisel - zaokrouhleni na cele cislo nahoru
        const arr = new Array(numberOfBlocks);     // vytvoreni pole o velikosti N dalsich poli pro uchovavani 32 bitovych celych cisel
        // cyklim pres vsechny 512 bitove bloky
        for (let i = 0; i < numberOfBlocks; i++) {
            arr[i] = new Array(16); // vytvoreni pole v poli o velikosti 16 prvku
            for (let j = 0; j < 16; j++) { // zakodovani 4 znaku do jednoho celeho cisla (tj. 64 znaku do 512 bitoveho bloku) - BIG-ENDIAN
                let position = i*64 + j*4;
                arr[i][j] = (inSequence.charCodeAt(position + 0) << 24) 
                          | (inSequence.charCodeAt(position + 1) << 16)
                          | (inSequence.charCodeAt(position + 2) << 8)
                          | (inSequence.charCodeAt(position + 3) << 0);
            }
        }

        // do posledni dvojice 32 bitovych cisel umistim delku retezce v bitech - BIG-ENDIAN
        const lengthLow = ((inSequence.length-1) * 8) >>> 0;
        const lengthHigh = ((inSequence.length-1) * 8) >>> 16 >>> 16;
        arr[numberOfBlocks-1][14] = Math.floor(lengthHigh);
        arr[numberOfBlocks-1][15] = lengthLow;

        // proces vypoctu hashe
        for (let i = 0; i < numberOfBlocks; i++) {
            // vytvoreni pole o velikosti 64 prvků
            const W = new Array(64);

            // prvnich 16 prvku z puvodniho pole se zkopiruje 
            for (let j = 0; j < 16; j++) {
                W[j] = arr[i][j];
            }

            // zkopirovanych 16 prvku se rozsiri do zbyvajicich 48 prvku (64-16=48) 
            for (let j = 16; j < 64; j++) {
                const s0 = MySha256.rotateRight(7, W[j-15]) ^ MySha256.rotateRight(18, W[j-15]) ^ (W[j-15] >>> 3);
                const s1 = MySha256.rotateRight(17, W[j-2]) ^ MySha256.rotateRight(19, W[j-2]) ^ (W[j-2] >>> 10);
                W[j] = (W[j-16] + s0 + W[j-7] + s1) >>> 0;
            }

            // inicializace pracovnich promennych na aktualni hashovaci hodnotu
            let a = H0;
            let b = H1;
            let c = H2;
            let d = H3;
            let e = H4;
            let f = H5;
            let g = H6;
            let h = H7;

            // hlavni smycka kompresni funkce
            for (let j = 0; j < 64; j++) {
                const S1 = MySha256.rotateRight(6, e) ^ MySha256.rotateRight(11, e) ^ MySha256.rotateRight(25, e);
                const ch = (e & f) ^ (~e & g);
                const temp1 = h + S1 + ch + K[j] + W[j];
                const S0 = MySha256.rotateRight(2,  a) ^ MySha256.rotateRight(13, a) ^ MySha256.rotateRight(22, a);
                const maj = (a & b) ^ (a & c) ^ (b & c);
                const temp2 = S0 + maj;
                
                h = g;
                g = f;
                f = e;
                e = (d + temp1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temp1 + temp2) >>> 0;
            }

            // vypocet nove hashovaci hodnoty (soucet puvodni a nove hodnoty)
            H0 = (H0 + a) >>> 0;
            H1 = (H1 + b) >>> 0;
            H2 = (H2 + c) >>> 0;
            H3 = (H3 + d) >>> 0;
            H4 = (H4 + e) >>> 0;
            H5 = (H5 + f) >>> 0;
            H6 = (H6 + g) >>> 0;
            H7 = (H7 + h) >>> 0;
        }

        // konverze H0 az H7 na hexadecimalni retezce
        const nullSeq = '00000000';
        H0 = (nullSeq + H0.toString(16)).slice(-8);
        H1 = (nullSeq + H1.toString(16)).slice(-8);
        H2 = (nullSeq + H2.toString(16)).slice(-8);
        H3 = (nullSeq + H3.toString(16)).slice(-8);
        H4 = (nullSeq + H4.toString(16)).slice(-8);
        H5 = (nullSeq + H5.toString(16)).slice(-8);
        H6 = (nullSeq + H6.toString(16)).slice(-8);
        H7 = (nullSeq + H7.toString(16)).slice(-8);

        return H0.concat(H1, H2, H3, H4, H5, H6, H7);
    }

}

export default MySha256;