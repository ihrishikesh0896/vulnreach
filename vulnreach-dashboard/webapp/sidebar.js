// Sidebar toggle logic
(function(){
  function applyInitialState(){
    try {
      const collapsed = localStorage.getItem('sidebar-collapsed') === '1';
      document.body.classList.toggle('sidebar-collapsed', collapsed);
    } catch(_) {}
  }

  function toggleSidebar(){
    const collapsed = document.body.classList.toggle('sidebar-collapsed');
    try { localStorage.setItem('sidebar-collapsed', collapsed ? '1' : '0'); } catch(_) {}
  }

  function attachToggleHandler(){
    const toggleBtn = document.querySelector('.sidebar-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', toggleSidebar);
    }
  }

  document.addEventListener('DOMContentLoaded', function(){
    applyInitialState();
    attachToggleHandler();
  });
})();