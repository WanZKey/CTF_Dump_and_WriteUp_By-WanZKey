https://gemini.google.com/share/fd58d979aa04
# WriteUp Dompet Crypto 2011

## Informasi Challenge

* **Nama Challenge**: Dompet Crypto 2011
* **Kategori**: Reverse Engineering (Android)
* **Author**: Archangel (@Ultramilk)
* **Poin**: 500
* **Deskripsi**: Admin melupakan password walletnya. Petunjuknya adalah "nama kota istimewa tempat dia ditinggal nikah".
* **File**: `bitsecure_wallet.apk`

## Langkah Penyelesaian

### 1. Analisis Statis (Decompilation)

Langkah pertama adalah melakukan dekompilasi file `bitsecure_wallet.apk` untuk membaca kode sumber aslinya. Tools yang digunakan adalah **Jadx GUI**.

Berikut adalah hasil dekompilasi dari `com.ctf.flaghunter.MainActivity`:

```java
package com.ctf.flaghunter;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

public final class MainActivity extends AppCompatActivity {
    private final String validUsername = "admin_wallet";
    private final String validPassword = "JogjaIstimewa"; // Kunci ditemukan disini

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final EditText editText = (EditText) findViewById(R.id.etUsername);
        final EditText editText2 = (EditText) findViewById(R.id.etPassword);
        ((Button) findViewById(R.id.btnLogin)).setOnClickListener(new View.OnClickListener() {
            @Override
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$0(editText, editText2, this, view);
            }
        });
    }

    public static final void onCreate$lambda$0(EditText editText, EditText editText2, MainActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        editText.getText().toString();
        String string = editText2.getText().toString(); // Mengambil input password
        Intent intent = new Intent(this$0, (Class<?>) FlagActivity.class);
        intent.putExtra("AUTH_TOKEN", string); // Password dikirim ke FlagActivity
        this$0.startActivity(intent);
        this$0.finish();
    }

    private final boolean validateCredentials(String u, String p) {
        return Intrinsics.areEqual(u, this.validUsername) && Intrinsics.areEqual(p, this.validPassword);
    }
}

```

### 2. Analisis Kode

Dari kode di atas, ditemukan variabel yang di-hardcode:

* `validUsername`: **"admin_wallet"**
* `validPassword`: **"JogjaIstimewa"**

Nilai `validPassword` ("JogjaIstimewa") sangat cocok dengan petunjuk di deskripsi soal ("nama kota istimewa"). Kode pada fungsi `onCreate$lambda$0` menunjukkan bahwa input password dari user (`string`) dikirim langsung ke `FlagActivity` melalui Intent dengan key `AUTH_TOKEN`. Ini mengindikasikan bahwa `FlagActivity` akan menggunakan string tersebut untuk mendekripsi flag.

### 3. Eksekusi (Emulation)

Karena validasi dan dekripsi terjadi secara runtime di `FlagActivity`, aplikasi perlu dijalankan untuk mendapatkan flag yang valid.

* **Platform**: [MyAndroid.org](https://www.myandroid.org/) (Online Android Emulator)
* **Langkah**:
1. Upload `bitsecure_wallet.apk` ke emulator online.
2. Jalankan aplikasi.
3. Login dengan password: `JogjaIstimewa`.
4. Aplikasi berhasil mendekripsi data dan menampilkan Master Private Key.



### 4. Hasil

**Flag:**
`FGTE{N3k_R4_N1nj4_R4_Ol3h_D1c1nt4}`
