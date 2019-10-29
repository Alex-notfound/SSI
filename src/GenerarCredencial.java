
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;
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
			System.out.println(
					"\tSintaxis:   java GenerarCredencial <fichero datos> <nombre paquete> <ficheros con las claves necesarias>");
			System.exit(1);
		}

		Scanner reader = new Scanner(new File(args[0]));
		String[] nombreCampos = { "nombre", "dni", "domicilio", "fechaCreacion", "lugarCreacion",
				"motivacionPeregrinaje" };
		Map<String, String> datos = new LinkedHashMap<>();
		int i = 0;
		while (reader.hasNextLine()) {
			datos.put(nombreCampos[i++], reader.nextLine());
		}
		String datosJsonOrigen = JSONUtils.map2json(datos);

		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits
		SecretKey clave = generadorDES.generateKey();
		PrivateKey clavePrivada = getPrivateKey(new File(args[2]));

		System.out.println("ENCRIPTANDO DATOS PEREGRINO - ");
		byte[] datosCifrados = encriptarDES(datosJsonOrigen.getBytes(), clave);

		System.out.println("ENCRIPTANDO CLAVE - ");
		byte[] claveCifrada = encriptarRSA(clave.getEncoded(), clavePrivada);

		System.out.println("HASH - ");
		byte[] resumen = hash(datosJsonOrigen);

		System.out.println("CREANDO FIRMA - ");
		byte[] firma = generarFirma(resumen, clavePrivada);

		Paquete paquete = new Paquete();
		String[] nombresBloque = { "datosPeregrino", "claveCifrada", "firma" };
		paquete.anadirBloque(nombresBloque[0], datosCifrados);
		paquete.anadirBloque(nombresBloque[1], claveCifrada);
		paquete.anadirBloque(nombresBloque[2], firma);
		PaqueteDAO.escribirPaquete(args[1], paquete);

	}

	private static byte[] generarFirma(byte[] resumen, PrivateKey clavePrivada) throws Exception {
		Signature firma = Signature.getInstance("MD5withRSA", "BC");
		firma.initSign(clavePrivada);
		firma.update(resumen);
		return firma.sign();
	}

	private static byte[] hash(String datos) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("MD5");
		messageDigest.update(datos.getBytes());
		return messageDigest.digest();
	}

	private static byte[] encriptarDES(byte[] datos, SecretKey clave) throws Exception {
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.ENCRYPT_MODE, clave);
		byte[] bufferCifrado = cifrador.update(datos);
		byte[] bufferCifrado2 = cifrador.doFinal(); // Completar cifrado (procesa relleno, puede devolver texto)

		byte[] toret = new byte[bufferCifrado.length + bufferCifrado2.length];
		System.arraycopy(bufferCifrado, 0, toret, 0, bufferCifrado.length);
		System.arraycopy(bufferCifrado2, 0, toret, bufferCifrado.length, bufferCifrado2.length);
		return toret;
	}

	private static byte[] encriptarRSA(byte[] resumen, PrivateKey clavePrivada) throws Exception {
		Cipher cifrador = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
		cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada);
		return cifrador.doFinal(resumen);
	}

	@SuppressWarnings("resource")
	private static PrivateKey getPrivateKey(File clavePrivada) throws Exception {
		byte[] buffer = new byte[(int) clavePrivada.length()];
		new FileInputStream(clavePrivada).read(buffer);
		KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
		return kf.generatePrivate(new PKCS8EncodedKeySpec(buffer));
	}
}