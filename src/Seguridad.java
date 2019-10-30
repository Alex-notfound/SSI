import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class Seguridad {

	public static String castToJsonString(String[] nombreCampos, String fileName) throws FileNotFoundException {
		try (Scanner reader = new Scanner(new File(fileName))) {
			Map<String, String> datos = new LinkedHashMap<>();
			int i = 0;
			while (reader.hasNextLine()) {
				datos.put(nombreCampos[i++], reader.nextLine());
			}
			return JSONUtils.map2json(datos);
		}
	}

	public static byte[] generarFirma(byte[] resumen, PrivateKey clavePrivada) throws Exception {
		Signature firma = Signature.getInstance("MD5withRSA", "BC");
		firma.initSign(clavePrivada);
		firma.update(resumen);
		return firma.sign();
	}

	public static boolean validarFirma(byte[] resumen, PublicKey clavePublica, byte[] firmaOrigen) throws Exception {
		Signature firma = Signature.getInstance("MD5withRSA", "BC");
		firma.initVerify(clavePublica);
		firma.update(resumen);
		return firma.verify(firmaOrigen);
	}

	public static byte[] hash(String datos) throws Exception {
		MessageDigest messageDigest = MessageDigest.getInstance("MD5");
		messageDigest.update(datos.getBytes());
		return messageDigest.digest();
	}

	public static byte[] encriptarDES(byte[] datos, SecretKey clave) throws Exception {
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.ENCRYPT_MODE, clave);
		byte[] bufferCifrado = cifrador.update(datos);
		byte[] bufferCifrado2 = cifrador.doFinal(); // Completar cifrado (procesa relleno, puede devolver texto)

		byte[] toret = new byte[bufferCifrado.length + bufferCifrado2.length];
		System.arraycopy(bufferCifrado, 0, toret, 0, bufferCifrado.length);
		System.arraycopy(bufferCifrado2, 0, toret, bufferCifrado.length, bufferCifrado2.length);
		return toret;
	}

	public static byte[] desencriptarDES(byte[] datosCifrados, SecretKey clave) throws Exception {
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador.init(Cipher.DECRYPT_MODE, clave);
		byte[] buffer = cifrador.update(datosCifrados);
		byte[] buffer2 = cifrador.doFinal(); // Completar cifrado (procesa relleno, puede devolver texto)

		byte[] toret = new byte[buffer.length + buffer2.length];
		System.arraycopy(buffer, 0, toret, 0, buffer.length);
		System.arraycopy(buffer2, 0, toret, buffer.length, buffer2.length);
		return toret;
	}

	public static byte[] encriptarRSA(byte[] resumen, Key clavePrivada) throws Exception {
		Cipher cifrador = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
		cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada);
		return cifrador.doFinal(resumen);
	}

	public static byte[] desencriptarRSA(byte[] resumen, Key clavePublica) throws Exception {
		Cipher cifrador = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
		cifrador.init(Cipher.DECRYPT_MODE, clavePublica);
		return cifrador.doFinal(resumen);
	}

	@SuppressWarnings("resource")
	public static PrivateKey getPrivateKey(String fileName) throws Exception {
		File clavePrivada = new File(fileName);
		byte[] buffer = new byte[(int) clavePrivada.length()];
		new FileInputStream(clavePrivada).read(buffer);
		KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
		return kf.generatePrivate(new PKCS8EncodedKeySpec(buffer));
	}

	@SuppressWarnings("resource")
	public static PublicKey getPublicKey(String fileName) throws Exception {
		File clavePublica = new File(fileName);
		byte[] buffer = new byte[(int) clavePublica.length()];
		new FileInputStream(clavePublica).read(buffer);
		KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
		return kf.generatePublic(new X509EncodedKeySpec(buffer));
	}

	public static void mostrarBytes(byte[] buffer) {
		System.out.write(buffer, 0, buffer.length);
	}

	public static void empaquetar(Paquete paquete, String fileName, String[] nombresBloque, List<byte[]> contenido) {
		for (int i = 0; i < nombresBloque.length; i++) {
			paquete.anadirBloque(nombresBloque[i], contenido.get(i));
		}
		PaqueteDAO.escribirPaquete(fileName, paquete);
	}
}
