
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerarCredencial {

	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {

		if (args.length < 1) {
			System.out.println("Generador de credencial");
			System.out.println("\tSintaxis:   java GenerarCredencial prefijo");
			System.exit(1);
		}
		Paquete paquete = new Paquete();

		System.out.println("Nombre del fichero con datos: ");
		File datosPeregrino = new File(new Scanner(System.in).nextLine());
		Scanner reader = new Scanner(datosPeregrino);

		encriptarDES(datosPeregrino);

		String[] nombresBloque = { "nombre", "dni", "domicilio", "fechaCreacion", "lugarCreacion",
				"motivacionPeregrinaje" };
		int i = 0;
		while (reader.hasNextLine()) {
			paquete.anadirBloque(nombresBloque[i++], reader.nextLine().getBytes(Charset.forName("UTF-8")));
		}
		PaqueteDAO.escribirPaquete(args[0], paquete);

	}

	private static byte[] hash(File datosPeregrino) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		MessageDigest messageDigest = MessageDigest.getInstance("MD5");

		byte[] buffer = new byte[1000];
		FileInputStream in = new FileInputStream(datosPeregrino);
		int leidos = in.read(buffer, 0, 1000);
		while (leidos != -1) {
			messageDigest.update(buffer, 0, leidos);
			leidos = in.read(buffer, 0, 1000);
		}
		in.close();
		return messageDigest.digest();
	}

	private static void encriptarDES(File datosPeregrino) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits
		SecretKey clave = generadorDES.generateKey();

		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");

		cifrador.init(Cipher.ENCRYPT_MODE, clave);

		// Modo cifrador:
		byte[] buffer = new byte[1000];
		byte[] bufferCifrado;

		FileInputStream in = new FileInputStream(datosPeregrino);
		FileOutputStream out = new FileOutputStream(new File("datosCifrados"));

		int bytesLeidos = in.read(buffer, 0, 1000);
		while (bytesLeidos != -1) { // Mientras no se llegue al final del fichero
			bufferCifrado = cifrador.update(buffer, 0, bytesLeidos); // Pasa texto claro leido al cifrador
			out.write(bufferCifrado);
			bytesLeidos = in.read(buffer, 0, 1000);
		}
		bufferCifrado = cifrador.doFinal(); // Completar cifrado (procesa relleno, puede devolver texto)
		out.write(bufferCifrado); // Escribir final del texto cifrado (si lo hay)

		in.close();
		out.close();
	}

	private static void encriptarRSA(File datosPeregrino) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		// PASO 1: Crear e inicializar el par de claves RSA DE 512 bits
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC"); // Hace uso del provider BC
		keyGen.initialize(512); // tamano clave 512 bits
		KeyPair clavesRSA = keyGen.generateKeyPair();
		PrivateKey clavePrivada = clavesRSA.getPrivate();
		PublicKey clavePublica = clavesRSA.getPublic();

		byte[] bufferPlano = leerLinea(new FileInputStream(datosPeregrino));

		Cipher cifrador = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
		//TODO: Esto tiene que ir separado
		cifrador.init(Cipher.ENCRYPT_MODE, clavePublica); // Cifra con la clave publica
		byte[] bufferCifrado = cifrador.doFinal(bufferPlano);
		cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada); // Cifra con la clave publica
		bufferCifrado = cifrador.doFinal(bufferPlano);
	}

	public static byte[] leerLinea(java.io.InputStream in) throws Exception {
		byte[] buffer1 = new byte[1000];
		int i = 0;
		byte c;
		c = (byte) in.read();
		while ((c != '\n') && (i < 1000)) {
			buffer1[i] = c;
			c = (byte) in.read();
			i++;
		}

		byte[] buffer2 = new byte[i];
		for (int j = 0; j < i; j++) {
			buffer2[j] = buffer1[j];
		}
		return (buffer2);
	}
}
