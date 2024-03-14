var form = document.forms[0];
form.addEventListener("submit", function (event) {
    var content = document.getElementById("content").value;
    var youtube_id = content.split("v=")[1];
    var youtube_src = "https://www.youtube.com/embed/" + youtube_id;
    var template = `<iframe width="560" height="315" src="YOUTUBE_SRC" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>`;
    var html = template.replace("YOUTUBE_SRC", youtube_src);
    document.getElementById("content").value = html;
});