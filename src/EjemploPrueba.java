
public class EjemploPrueba {

	public static void main(String[] args) throws Exception {

		String[] generarClavesPeregrino = { "clavePeregrino" };
		GenerarClaves.main(generarClavesPeregrino);
		String[] generarClavesOficina = { "claveOficina" };
		GenerarClaves.main(generarClavesOficina);
		String[] generarClavesAlbergue = { "claveAlbergue1" };
		GenerarClaves.main(generarClavesAlbergue);
		String[] generarClavesAlbergue2 = { "claveAlbergue2" };
		GenerarClaves.main(generarClavesAlbergue2);

		String[] generarCredencial = { "CPVPack", "claveOficina.publica", "clavePeregrino.privada" };
		GenerarCredencial.main(generarCredencial);

		String[] sellarCredencial = { "CPVPack", "albergue1", "claveAlbergue1.privada", "claveOficina.publica" };
		SellarCredencial.main(sellarCredencial);

		String[] sellarCredencial2 = { "CPVPack", "albergue2", "claveAlbergue2.privada", "claveOficina.publica" };
		SellarCredencial.main(sellarCredencial2);

		String[] desempaquetarCredencial2 = { "CPVPack", "3", "albergue1", "claveAlbergue1.publica", "albergue2",
				"claveAlbergue2.publica", "albergue3", "claveAlbergue3.publica", "claveOficina.privada",
				"clavePeregrino.publica" };
		DesempaquetarCredencial.main(desempaquetarCredencial2);

	}

}
