document.addEventListener('DOMContentLoaded', () => {
  // Seleccionamos los tabs y los contenidos asociados
  const tabs = document.querySelectorAll('.tabs li');
  const tabContents = document.querySelectorAll('.column > div[id]');

  function activateTab(targetId) {
    // Desactivar todos los tabs y ocultar su contenido
    tabs.forEach(tab => tab.classList.remove('is-active'));
    tabContents.forEach(content => content.classList.add('is-hidden'));

    // Activar el tab seleccionado y mostrar su contenido
    const activeTab = document.querySelector(`.tabs li a[href="#${targetId}"]`).parentElement;
    activeTab.classList.add('is-active');
    document.getElementById(targetId).classList.remove('is-hidden');
  }

  // Cambiar al tab correspondiente al cargar la página (usar hash de la URL si existe)
  const initialTab = window.location.hash.slice(1) || 'profile';
  activateTab(initialTab);

  // Cambiar de tab al hacer clic
  tabs.forEach(tab => {
    tab.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = tab.querySelector('a').getAttribute('href').slice(1);
      activateTab(targetId);

      // Actualizar el hash en el URL
      window.location.hash = targetId;
    });
  });
});
