/*
 * Planned for general subroutines which are useful but not defined in the
 * kernel. Currently contains only debug related stuff.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/mac.h>
#include <sys/jail.h>
#include <sys/sx.h>
#include <sys/mount.h>
#include <sys/selinfo.h>

#include "fuse.h"
#include "fuse_ipc.h"

#if _DEBUG || _DEBUG2G || _DEBUG3G || defined(INVARIANTS) || FUSELIB_CONFORM_BIOREAD
int
isbzero(void *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i++)
	{
		if (((char *)buf)[i])
			return (0);
	}

	return (1);
}
#endif /* _DEBUG || _DEBUG2G || _DEBUG3G */


#if _DEBUG || _DEBUG2G || _DEBUG3G || FMASTER
static char *pptable[] = { "\\000", "\\001", "\\002", "\\003", "\\004", "\\005", "\\006", "\\a", "\\010", "\\t", "\\n", "\\v", "\\f", "\\r", "\\016", "\\017", "\\020", "\\021", "\\022", "\\023", "\\024", "\\025", "\\026", "\\027", "\\030", "\\031", "\\032", "\\e", "\\034", "\\035", "\\036", "\\037", " ", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", "@", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "[", "\\", "]", "^", "_", "`", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "{", "|", "}", "~", "\\177", "\\200", "\\201", "\\202", "\\203", "\\204", "\\205", "\\206", "\\207", "\\210", "\\211", "\\212", "\\213", "\\214", "\\215", "\\216", "\\217", "\\220", "\\221", "\\222", "\\223", "\\224", "\\225", "\\226", "\\227", "\\230", "\\231", "\\232", "\\233", "\\234", "\\235", "\\236", "\\237", "\\240", "\\241", "\\242", "\\243", "\\244", "\\245", "\\246", "\\247", "\\250", "\\251", "\\252", "\\253", "\\254", "\\255", "\\256", "\\257", "\\260", "\\261", "\\262", "\\263", "\\264", "\\265", "\\266", "\\267", "\\270", "\\271", "\\272", "\\273", "\\274", "\\275", "\\276", "\\277", "\\300", "\\301", "\\302", "\\303", "\\304", "\\305", "\\306", "\\307", "\\310", "\\311", "\\312", "\\313", "\\314", "\\315", "\\316", "\\317", "\\320", "\\321", "\\322", "\\323", "\\324", "\\325", "\\326", "\\327", "\\330", "\\331", "\\332", "\\333", "\\334", "\\335", "\\336", "\\337", "\\340", "\\341", "\\342", "\\343", "\\344", "\\345", "\\346", "\\347", "\\350", "\\351", "\\352", "\\353", "\\354", "\\355", "\\356", "\\357", "\\360", "\\361", "\\362", "\\363", "\\364", "\\365", "\\366", "\\367", "\\370", "\\371", "\\372", "\\373", "\\374", "\\375", "\\376", "\\377" };

void
uprettyprint(char *buf, size_t len)
{
	int i;

	uprintf("\"");	
	for (i=0; i < len; i++) {
		uprintf("%s",pptable[((uint8_t *)buf)[i]]);
	} 
	uprintf("\"");
}

void
prettyprint(char *buf, size_t len)
{
	int i;

	printf("\"");	
	for (i=0; i < len; i++) {
		printf("%s",pptable[((uint8_t *)buf)[i]]);
	} 
	printf("\"");
}

void
fprettyprint(struct fuse_iov *fiov, size_t dlen)
{
	int i;

	uprintf("\"");	
	for (i=0; i < MIN(fiov->len, dlen); i++) {
		uprintf("%s",pptable[((uint8_t *)fiov->base)[i]]);
	} 
	uprintf("\"");
	uprintf("%s\n", dlen < fiov->len ? "..." : "");
}
#endif /* _DEBUG || _DEBUG2G || _DEBUG3G || FMASTER */
