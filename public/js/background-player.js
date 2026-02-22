(function() {
    if (typeof localStorage === 'undefined') return;
    if (localStorage.getItem('backgroundPlaying') !== '1') return;
    if (!localStorage.getItem('backgroundUrl') && !localStorage.getItem('backgroundYoutubeId')) return;
    var opts = 'width=320,height=70,left=100,top=100,menubar=no,toolbar=no,status=no';
    var name = 'appBackgroundPlayer';
    var existing = window.open('', name);
    if (!existing || existing.closed) {
        window.open('/background-player', name, opts);
    } else {
        existing.focus();
    }
})();
