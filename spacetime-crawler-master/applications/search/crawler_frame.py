
import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager, Link
from spacetime.client.IApplication import IApplication
from spacetime.client.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
import re, os
from time import time
from collections import defaultdict
from tldextract import tldextract

try:
	# For python 2
	from urlparse import urlparse, parse_qs, urljoin
except ImportError:
	# For python 3
	from urllib.parse import urlparse, parse_qs, urljoin

	
logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"
url_count = (set() 
	if not os.path.exists("successful_urls.txt") else 
	set([line.strip() for line in open("successful_urls.txt").readlines() if line.strip() != ""]))
MAX_LINKS_TO_DOWNLOAD = 3

#variables we declared
page_to_outlinkscount = defaultdict(int)
count_invalid = 0
subdomain_to_urls = defaultdict(set)
good_urls_time = list()

@Producer(ProducedLink, Link)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):

	def __init__(self, frame):
		self.starttime = time()
		# Set app_id <student_id1>_<student_id2>...
		self.app_id = "71536611_27037711_18677378"
		# Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
		# If Graduate student, change the UnderGrad part to Grad.
		self.UserAgentString = "IR S17 UnderGrad 71536611, 27037711, 18677378"
		
		self.frame = frame
		assert(self.UserAgentString != None)
		assert(self.app_id != "")
		if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
		    self.done = True
                self.validtime = time()
		

	def initialize(self):
		self.count = 0
		l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
		print l.full_url
		self.frame.add(l)

	def update(self):
		global count_invalid
		global subdomain_to_urls
		
		for g in self.frame.get_new(OneUnProcessedGroup):
			print "Got a Group"
			outputLinks, urlResps = process_url_group(g, self.UserAgentString)
			for urlResp in urlResps:
				if urlResp.bad_url and self.UserAgentString not in set(urlResp.dataframe_obj.bad_url):
					urlResp.dataframe_obj.bad_url += [self.UserAgentString]
			for l in outputLinks:
				if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
					lObj = ProducedLink(l, self.UserAgentString)
					self.frame.add(lObj)
					subdomain_to_urls[get_subdomain(l)].add(l)
					good_urls_time.append(time()-self.validtime)
					self.validtime = time()
				else:
					count_invalid += 1
		if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
			self.done = True

	def shutdown(self):
		global page_to_outlinkscount
		global count_invalid
		global subdomain_to_urls
		global good_urls_time
		
		with open("analysis_file.txt", 'w') as analysis_file:
			#point number 1 in analysis
			for subdomain, urls in subdomain_to_urls.items():
				analysis_file.write("Subdomain: {} Number of Different URLs: {}\n".format(subdomain, len(urls)))
			#point number 2 in analysis
			analysis_file.write("\nNumber of invalid links: {}\n".format(count_invalid))
			#point number 3 in analysis
			if page_to_outlinkscount:
                                page_most_out_links = sorted(page_to_outlinkscount.keys(), key=lambda page:page_to_outlinkscount[page], reverse=True)[0]
                                analysis_file.write("\nPage with the most outlinks: {} ({})".format(page_most_out_links, page_to_outlinkscount[page_most_out_links]))
                        if good_urls_time:
                                analysis_file.write("\nAverage seconds it takes to find good urls: {}\n".format(sum(good_urls_time)/len(good_urls_time)))
		
		print "downloaded ", len(url_count), " in ", time() - self.starttime, " seconds."

def save_count(urls):
	global url_count
	urls = set(urls).difference(url_count)
	url_count.update(urls)
	if len(urls):
		with open("successful_urls.txt", "a") as surls:
			surls.write(("\n".join(urls) + "\n").encode("utf-8"))

def process_url_group(group, useragentstr):
	rawDatas, successfull_urls = group.download(useragentstr, is_valid)
	save_count(successfull_urls)
	return extract_next_links(rawDatas), rawDatas
	
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
	outputLinks = list()
	'''
	rawDatas is a list of objs -> [raw_content_obj1, raw_content_obj2, ....]
	Each obj is of type UrlResponse	 declared at L28-42 datamodel/search/datamodel.py
	the return of this function should be a list of urls in their absolute form
	Validation of link via is_valid function is done later (see line 42).
	It is not required to remove duplicates that have already been downloaded. 
	The frontier takes care of that.

	Suggested library: lxml
	'''
	global page_to_outlinkscount
	
	for rco in rawDatas:
		try:
                        #parsing html content for href attributes of all a tags
			tree = html.fromstring(rco.content)
			links = tree.cssselect('a')
			for link in links:
				if 'href' in link.attrib:
                                        url = rco.final_url if rco.final_url else rco.url
					page_to_outlinkscount[url] += 1
					outputLinks.append(get_absolute_url(rco.url, rco.final_url, link.attrib['href']))
		except etree.XMLSyntaxError, e:
			pass
	return outputLinks

def is_valid(url):
	'''
	Function returns True or False based on whether the url has to be downloaded or not.
	Robot rules and duplication rules are checked separately.

	This is a great place to filter out crawler traps.
	'''
	parsed = urlparse(url)
	
	#checking scheme
	if parsed.scheme not in set(["http", "https"]):
		return False
	
	path = parsed.path
	path_components = path.split("/")
	
	#filtering out urls with a lot of subdirectories
	if len(path_components) >= 6:
		return False
	#filtering out urls with calendar in the path
	if re.match("calendar", path):
		return False
	#filtering out sites using Wix platform
	if len(path) >= 300:
		return False
	#filtering out urls with repeated directories 
	d = defaultdict(int)
	for dir in path_components[:-1]:
		d[dir] += 1
		if d[dir] >= 3:
			return False
	
	#filtering out urls with query strings with any keywords that might be calendar related
	query_string = parsed.query
	kv_pairs = query_string.split("&")
	for kv_pair in kv_pairs:
		if kv_pair.split("=")[0] in {"week", "day", "year", "date"}:
			return False
	
	try:
		return ".ics.uci.edu" in parsed.hostname \
			and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4" \
			+ "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
			+ "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
			+ "|thmx|mso|arff|rtf|jar|csv" \
			+ "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())
	except TypeError:
		print ("TypeError for ", parsed)

'''
HELPER FUNCTIONS
'''

#checks whether url is in absolute form
def is_absolute(url):
        return bool(urlparse(url).netloc)

#converts a potentially relative path in link to an absolute url
def get_absolute_url(base_url, final_url, link):
        if is_absolute(link):
                return link
        else:
                base_url = final_url if final_url else base_url
                return urljoin(base_url, link)

#gets subdomain of ics.uci.edu from hostname
def get_subdomain(url):
        hostname = urlparse(url).hostname
        result = hostname.rsplit('ics', 1)[0]
        result = result.rsplit('.', 1)[0]
        return result
