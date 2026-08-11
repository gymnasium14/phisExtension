const accept = document.getElementById('accept');
const deny = document.getElementById('deny');


deny.addEventListener('click', function(){
    if (document.referrer) {
        history.back();
    } else {
        // Если истории нет, перенаправляем на главную
        window.location.href = '/';
    }
});
accept.addEventListener('click', function(){
    if (urlParams.has('link'))
    {
        window.location.href = urlParams.get('char');
    }
});