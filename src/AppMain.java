
public class AppMain {

	public static void main(String[] args) throws Exception {

		String[] generarClavesPeregrino = { "clavePeregrino" };
		GenerarClaves.main(generarClavesPeregrino);
		String[] generarClavesOficina = { "claveOficina" };
		GenerarClaves.main(generarClavesOficina);
		String[] generarClavesAlbergue = { "claveAlbergue1" };
		GenerarClaves.main(generarClavesAlbergue);
		String[] generarClavesAlbergue2 = { "claveAlbergue2" };
		GenerarClaves.main(generarClavesAlbergue2);

// java GenerarCredencial datos_peregrino.txt CPVPack claveOficina.publica clavePeregrino.privada

		String[] generarCredencial = { "datos_peregrino.txt", "CPVPack", "claveOficina.publica", "clavePeregrino.privada" };
		GenerarCredencial.main(generarCredencial);

// java SellarCredencial CPVPack albergue1 claveAlbergue.privada claveOficina.publica

		String[] sellarCredencial = { "datos_albergue1.txt", "CPVPack", "albergue1", "claveAlbergue1.privada",
				"claveOficina.publica" };
		SellarCredencial.main(sellarCredencial);

// java DesempaquetarCredencial CPVPack 0 claveOficina.privada clavePeregrino.publica
// java DesempaquetarCredencial CPVPack 1 albergue1 claveAlbergue1.publica claveOficina.privada clavePeregrino.publica

//		String[] desempaquetarCredencial = { "CPVPack", "1", "albergue1", "claveAlbergue1.publica", "claveOficina.privada",
//				"clavePeregrino.publica" };
//		DesempaquetarCredencial.main(desempaquetarCredencial);

// java SellarCredencial CPVPack albergue2 claveAlbergue2.privada claveOficina.publica

		String[] sellarCredencial2 = { "datos_albergue2.txt", "CPVPack", "albergue2", "claveAlbergue2.privada",
				"claveOficina.publica" };
		SellarCredencial.main(sellarCredencial2);

// java DesempaquetarCredencial CPVPack 1 albergue1 claveAlbergue1.publica albergue2 claveAlbergue2.publica claveOficina.privada clavePeregrino.publica

		String[] desempaquetarCredencial2 = { "CPVPack", "2", "albergue1", "claveAlbergue1.publica", "albergue2",
				"claveAlbergue2.publica", "claveOficina.privada", "clavePeregrino.publica" };
		DesempaquetarCredencial.main(desempaquetarCredencial2);
	}

}
