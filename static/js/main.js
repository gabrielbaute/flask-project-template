document.addEventListener('DOMContentLoaded', () => {
  // Seleccionar el botón de hamburguesa y el menú correspondiente
  const burger = document.querySelector('.navbar-burger');
  const menu = document.querySelector('.navbar-menu');

  if (burger && menu) {
    // Agregar un evento 'click' al botón de hamburguesa
    burger.addEventListener('click', () => {
      // Alternar las clases 'is-active' en el botón y en el menú
      burger.classList.toggle('is-active');
      menu.classList.toggle('is-active');
    });
  }

  // Lógica para desplegar los dropdowns dentro del menú
  const dropdowns = document.querySelectorAll('.navbar-item.has-dropdown');
  dropdowns.forEach(dropdown => {
    const trigger = dropdown.querySelector('.navbar-link');
    if (trigger) {
      trigger.addEventListener('click', (e) => {
        e.preventDefault(); // Evitar que el enlace recargue la página
        dropdown.classList.toggle('is-active');
      });
    }
  });

  // Seleccionar tabs y contenidos asociados
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

document.addEventListener('click', (event) => { // Cerrar notificaciones al hacer clic en el botón de eliminar
  if (event.target.matches('.notification .delete')) {
    const notification = event.target.parentElement;
    notification.remove();
  }
});