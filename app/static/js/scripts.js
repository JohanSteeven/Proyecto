// Función para crear la tabla y aplicar colores según el valor
function createTable(obj) {
  if (typeof obj !== "object" || obj === null) return document.createTextNode(String(obj));

  const table = document.createElement("table");
  for (const key in obj) {
    const tr = document.createElement("tr");
    const th = document.createElement("th");
    th.textContent = key;

    const td = document.createElement("td");

    if (typeof obj[key] === "object" && obj[key] !== null) {
      td.appendChild(createTable(obj[key]));
    } else {
      const value = String(obj[key]);  // Convertir el valor a cadena para usar includes()
      td.textContent = value;

      // Colorear las celdas según el valor
      if (value.includes("open") || value.includes("enabled")) {
        td.classList.add("safe");
      } else if (value.includes("filtered") || value.includes("error")) {
        td.classList.add("intermediate");
      } else if (value.includes("closed") || value.includes("disabled")) {
        td.classList.add("vulnerable");
      } else {
        td.classList.add("no-data");
      }
    }

    tr.appendChild(th);
    tr.appendChild(td);
    table.appendChild(tr);
  }
  return table;
}

document.getElementById("form").addEventListener("submit", async function(e) {
  e.preventDefault();
  const ip = document.getElementById("ip").value;
  const resultadosDiv = document.getElementById("resultados");
  resultadosDiv.innerHTML = "Cargando...";
  try {
    const res = await fetch(`/evaluacion/?ip_o_dominio=${encodeURIComponent(ip)}`, {
      method: "POST"
    });
    const data = await res.json();
    resultadosDiv.innerHTML = "";

    for (const section in data) {
      const h2 = document.createElement("h2");
      h2.textContent = section.charAt(0).toUpperCase() + section.slice(1);
      resultadosDiv.appendChild(h2);
      resultadosDiv.appendChild(createTable(data[section]));
    }
  } catch (error) {
    resultadosDiv.textContent = "Error: " + error;
  }
});
