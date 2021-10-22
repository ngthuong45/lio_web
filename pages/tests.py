from django.test import SimpleTestCase
from django.urls import reverse, resolve
from pages.views import HomePageView


class HomepageTests(SimpleTestCase):

    def setUp(self):
        url = reverse('homepage')
        self.response = self.client.get(url)

    def test_homepage_status_code(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_homepage_template(self):
        response = self.client.get('/')
        self.assertTemplateUsed(response, 'pages/homepage.html')

    def test_homepage_contains_correct_html(self):
        response = self.client.get('/')
        self.assertContains(response, 'Homepage')

    def test_homepage_does_not_contain_incorrect_html(self):
        response = self.client.get('/')
        self.assertNotContains(response, 'Hi there! I should not be on the page.')

    def test_homepage_url_resolves_homepageview(self):
        view = resolve('/')
        self.assertEqual(view.func.__name__, HomePageView.as_view().__name__)
