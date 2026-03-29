"""URL routing for the USMD-RDSH web dashboard."""

from django.urls import path

from . import views

urlpatterns = [
    path("",               views.index,           name="index"),
    path("login/",         views.login_view,      name="login"),
    path("logout/",        views.logout_view,     name="logout"),
    path("dashboard/",     views.dashboard,       name="dashboard"),
    path("node/<str:address>/", views.node_detail, name="node_detail"),
    path("api/nodes/",     views.api_nodes,       name="api_nodes"),
    path(
        "api/node/<str:address>/",
        views.api_node_snapshot,
        name="api_node_snapshot",
    ),
    path("api/stream/",    views.api_stream,      name="api_stream"),
]
